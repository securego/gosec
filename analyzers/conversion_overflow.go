// (c) Copyright gosec's authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
	"fmt"
	"go/token"
	"math"
	"regexp"
	"strconv"

	"golang.org/x/exp/constraints"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

type integer struct {
	signed bool
	size   int
	min    int
	max    uint
}

func newConversionOverflowAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runConversionOverflow,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runConversionOverflow(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, fmt.Errorf("building ssa representation: %w", err)
	}

	issues := []*issue.Issue{}
	for _, mcall := range ssaResult.SSA.SrcFuncs {
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				switch instr := instr.(type) {
				case *ssa.Convert:
					src := instr.X.Type().Underlying().String()
					dst := instr.Type().Underlying().String()
					if isIntOverflow(src, dst) {
						if isSafeConversion(instr) {
							continue
						}
						issue := newIssue(pass.Analyzer.Name,
							fmt.Sprintf("integer overflow conversion %s -> %s", src, dst),
							pass.Fset,
							instr.Pos(),
							issue.High,
							issue.Medium,
						)
						issues = append(issues, issue)
					}
				}
			}
		}
	}

	if len(issues) > 0 {
		return issues, nil
	}
	return nil, nil
}

func isIntOverflow(src string, dst string) bool {
	srcInt, err := parseIntType(src)
	if err != nil {
		return false
	}

	dstInt, err := parseIntType(dst)
	if err != nil {
		return false
	}

	return srcInt.min < dstInt.min || srcInt.max > dstInt.max
}

func parseIntType(intType string) (integer, error) {
	re := regexp.MustCompile(`^(?P<type>u?int)(?P<size>\d{1,2})?$`)
	matches := re.FindStringSubmatch(intType)
	if matches == nil {
		return integer{}, fmt.Errorf("no integer type match found for %s", intType)
	}

	it := matches[re.SubexpIndex("type")]
	is := matches[re.SubexpIndex("size")]

	signed := it == "int"

	// use default system int type in case size is not present in the type
	intSize := strconv.IntSize
	if is != "" {
		var err error
		intSize, err = strconv.Atoi(is)
		if err != nil {
			return integer{}, fmt.Errorf("failed to parse the integer type size: %w", err)
		}
	}

	if intSize != 8 && intSize != 16 && intSize != 32 && intSize != 64 && is != "" {
		return integer{}, fmt.Errorf("invalid bit size: %d", intSize)
	}

	var min int
	var max uint

	if signed {
		max = (1 << uint(intSize-1)) - 1
		min = -int(max) - 1
	} else {
		max = (1 << uint(intSize)) - 1
		min = 0
	}

	return integer{
		signed: signed,
		size:   intSize,
		min:    min,
		max:    max,
	}, nil
}

func isSafeConversion(instr *ssa.Convert) bool {
	dstType := instr.Type().Underlying().String()

	// Check for constant conversions
	if constVal, ok := instr.X.(*ssa.Const); ok {
		if isConstantInRange(constVal, dstType) {
			return true
		}
	}

	// Check for string to integer conversions with specified bit size
	if isStringToIntConversion(instr, dstType) {
		return true
	}

	// Check for explicit range checks
	if hasExplicitRangeCheck(instr, dstType) {
		return true
	}

	return false
}

func isConstantInRange(constVal *ssa.Const, dstType string) bool {
	value, err := strconv.ParseInt(constVal.Value.String(), 10, 64)
	if err != nil {
		return false
	}

	dstInt, err := parseIntType(dstType)
	if err != nil {
		return false
	}

	if dstInt.signed {
		return value >= -(1<<(dstInt.size-1)) && value <= (1<<(dstInt.size-1))-1
	}
	return value >= 0 && value <= (1<<dstInt.size)-1
}

func isStringToIntConversion(instr *ssa.Convert, dstType string) bool {
	// Traverse the SSA instructions to find the original variable
	original := instr.X
	for {
		switch v := original.(type) {
		case *ssa.Call:
			if v.Call.StaticCallee() != nil && (v.Call.StaticCallee().Name() == "ParseInt" || v.Call.StaticCallee().Name() == "ParseUint") {
				if len(v.Call.Args) == 3 {
					if bitSize, ok := v.Call.Args[2].(*ssa.Const); ok {
						signed := v.Call.StaticCallee().Name() == "ParseInt"
						bitSizeValue, err := strconv.Atoi(bitSize.Value.String())
						if err != nil {
							return false
						}
						dstInt, err := parseIntType(dstType)
						if err != nil {
							return false
						}
						isSafe := bitSizeValue <= dstInt.size && signed == dstInt.signed
						return isSafe
					}
				}
			}
			return false
		case *ssa.Phi:
			original = v.Edges[0]
		case *ssa.Extract:
			original = v.Tuple
		default:
			return false
		}
	}
}

func hasExplicitRangeCheck(instr *ssa.Convert, dstType string) bool {
	fmt.Println("")
	dstInt, err := parseIntType(dstType)
	if err != nil {
		return false
	}

	srcInt, err := parseIntType(instr.X.Type().String())
	if err != nil {
		return false
	}

	minValue := srcInt.min
	maxValue := srcInt.max

	if minValue > dstInt.min && maxValue < dstInt.max {
		return true
	}

	visitedIfs := make(map[*ssa.If]bool)
	for _, block := range instr.Parent().Blocks {
		for _, blockInstr := range block.Instrs {
			switch v := blockInstr.(type) {
			case *ssa.If:
				currMinValue, currMaxValue, isRangeCheck, _ := getResultRange(v, instr, visitedIfs)

				if isRangeCheck {
					minValue = max(minValue, &currMinValue)
					maxValue = min(maxValue, &currMaxValue)
				}
			case *ssa.Call:
				// len(slice) results in an int that is guaranteed >= 0, which
				// satisfies the lower bound check for int -> uint conversion
				if v != instr.X {
					continue
				}
				if fn, isBuiltin := v.Call.Value.(*ssa.Builtin); isBuiltin {
					switch fn.Name() {
					case "len", "cap":
						minValue = 0
					}
				}
			case *ssa.Convert:
				if v == instr {
					break
				}
			}

			if minValue >= dstInt.min && maxValue <= dstInt.max {
				return true
			}
		}
	}
	return false
}

func getResultRange(ifInstr *ssa.If, instr *ssa.Convert, visitedIfs map[*ssa.If]bool) (minValue int, maxValue uint, isRangeChk, convertFound bool) {
	minValue = math.MinInt
	maxValue = math.MaxUint

	if visitedIfs[ifInstr] {
		return minValue, maxValue, false, false
	}
	visitedIfs[ifInstr] = true

	cond := ifInstr.Cond

	var thenBounds, elseBounds branchBounds

	if binOp, ok := cond.(*ssa.BinOp); ok && isRangeCheck(binOp, instr.X) {
		isRangeChk = true

		// Check the true branch
		thenBounds = walkBranchForConvert(ifInstr.Block().Succs[0], instr, visitedIfs)

		x, y := binOp.X, binOp.Y
		operandsFlipped := false
		if x != instr.X {
			y = x
			operandsFlipped = true
		}
		constVal, ok := y.(*ssa.Const)
		if !ok {
			return minValue, maxValue, false, false
		}

		switch binOp.Op {
		case token.LEQ, token.LSS:
			if thenBounds.convertFound && !operandsFlipped {
				maxValue = uint(constVal.Uint64())
				if binOp.Op == token.LEQ {
					maxValue--
				}
				break
			}
			minValue = int(constVal.Int64())
			if binOp.Op == token.GTR {
				minValue++
			}
		case token.GEQ, token.GTR:
			if thenBounds.convertFound && !operandsFlipped {
				minValue = int(constVal.Int64())
				if binOp.Op == token.GEQ {
					minValue++
				}
				break
			}
			maxValue = uint(constVal.Uint64())
			if binOp.Op == token.LSS {
				maxValue--
			}
		}
	}

	if !isRangeChk {
		return minValue, maxValue, isRangeChk, convertFound
	}

	elseBounds = walkBranchForConvert(ifInstr.Block().Succs[1], instr, visitedIfs)

	if thenBounds.convertFound {
		return max(minValue, thenBounds.minValue), min(maxValue, thenBounds.maxValue), true, true
	} else if elseBounds.convertFound {
		return max(minValue, elseBounds.minValue), min(maxValue, elseBounds.maxValue), true, true
	}

	return minValue, maxValue, isRangeChk, convertFound
}

type branchBounds struct {
	minValue     *int
	maxValue     *uint
	convertFound bool
}

func walkBranchForConvert(block *ssa.BasicBlock, instr *ssa.Convert, visitedIfs map[*ssa.If]bool) branchBounds {
	bounds := branchBounds{}
	convertFound := false
	for _, blockInstr := range block.Instrs {
		switch v := blockInstr.(type) {
		case *ssa.If:
			currMinValue, currMaxValue, isRangeCheck, cnvrtFound := getResultRange(v, instr, visitedIfs)
			convertFound = convertFound || cnvrtFound

			if isRangeCheck {
				bounds.minValue = toPtr(min(currMinValue, bounds.minValue))
				bounds.maxValue = toPtr(max(currMaxValue, bounds.maxValue))
			}
		case *ssa.Call:
			if v != instr.X {
				continue
			}
			if fn, isBuiltin := v.Call.Value.(*ssa.Builtin); isBuiltin {
				switch fn.Name() {
				case "len", "cap":
					bounds.minValue = toPtr(0)
				}
			}
		case *ssa.Convert:
			if v == instr {
				bounds.convertFound = true
				break
			}
		}
	}

	bounds.convertFound = bounds.convertFound || convertFound

	return bounds
}

func isRangeCheck(v ssa.Value, x ssa.Value) bool {
	switch op := v.(type) {
	case *ssa.BinOp:
		return (op.X == x || op.Y == x) &&
			(op.Op == token.LSS || op.Op == token.LEQ || op.Op == token.GTR || op.Op == token.GEQ)
	case *ssa.UnOp:
		if op.Op == token.NOT {
			if binOp, ok := op.X.(*ssa.BinOp); ok {
				return (binOp.X == x || binOp.Y == x) &&
					(binOp.Op == token.EQL || binOp.Op == token.NEQ ||
						binOp.Op == token.LSS || binOp.Op == token.LEQ ||
						binOp.Op == token.GTR || binOp.Op == token.GEQ)
			}
		}
	}
	return false
}

func min[T constraints.Integer](a T, b *T) T {
	if b == nil {
		return a
	}
	if a < *b {
		return a
	}
	return *b
}

func max[T constraints.Integer](a T, b *T) T {
	if b == nil {
		return a
	}
	if a > *b {
		return a
	}
	return *b
}

func toPtr[T any](a T) *T {
	return &a
}
