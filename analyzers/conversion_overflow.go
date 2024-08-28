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
	"regexp"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

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
	dstInt, err := parseIntType(dstType)
	if err != nil {
		return false
	}

	srcInt, err := parseIntType(instr.X.Type().String())
	if err != nil {
		return false
	}

	minBoundChecked := checkSourceMinBound(srcInt, dstInt)
	maxBoundChecked := checkSourceMaxBound(srcInt, dstInt)

	// If both bounds are already checked, return true
	if minBoundChecked && maxBoundChecked {
		return true
	}

	visitedIfs := make(map[*ssa.If]bool)
	for _, block := range instr.Parent().Blocks {
		var minChecked, maxChecked bool
		for _, blockInstr := range block.Instrs {
			switch v := blockInstr.(type) {
			case *ssa.If:
				minChecked, maxChecked = checkIfForRangeCheck(v, instr, dstInt, visitedIfs)
			case *ssa.Call:
				// len(slice) results in an int that is guaranteed >= 0, which
				// satisfies the lower bound check for int -> uint conversion
				if v != instr.X {
					continue
				}
				if fn, isBuiltin := v.Call.Value.(*ssa.Builtin); isBuiltin && fn.Name() == "len" && !dstInt.signed {
					minChecked = true
				}
			case *ssa.Convert:
				if v == instr {
					break
				}
			}
			minBoundChecked = minBoundChecked || minChecked
			maxBoundChecked = maxBoundChecked || maxChecked

			if minBoundChecked && maxBoundChecked {
				return true
			}
		}
	}
	return false
}

func checkIfForRangeCheck(ifInstr *ssa.If, instr *ssa.Convert, dstInt integer, visitedIfs map[*ssa.If]bool) (minBoundChecked, maxBoundChecked bool) {
	if visitedIfs[ifInstr] {
		// If the if instruction has already been visited, we can skip it
		return false, false
	}
	visitedIfs[ifInstr] = true

	// check Instrs for other bound checks
	condBlock := ifInstr.Block()
	if succIf, ok := condBlock.Succs[1].Instrs[1].(*ssa.If); ok {
		// this is an OR condition and should be sufficient if it contains the other bound check
		minBoundChecked, maxBoundChecked = checkIfForRangeCheck(succIf, instr, dstInt, visitedIfs)
	}

	// check the instructions of the if block for other bound checks
	for _, succ := range condBlock.Succs {
		for _, blockInstr := range succ.Instrs {
			if succIf, ok := blockInstr.(*ssa.If); ok {
				// this is an AND condition and is insufficient to check the bounds but we need to visit it
				// because walking the parent block will visit it again
				_, _ = checkIfForRangeCheck(succIf, instr, dstInt, visitedIfs)
			}
		}
	}

	cond := ifInstr.Cond
	// Check if the condition is a bound check
	if binOp, ok := cond.(*ssa.BinOp); ok {
		if isBoundCheck(binOp, instr.X) {
			constVal, isOnLeft := constFromBoundCheck(binOp)
			if constVal == nil {
				return false, false
			}

			value := constVal.Int64()

			if isOnLeft {
				if binOp.Op == token.LSS || binOp.Op == token.LEQ {
					newMaxCheck := checkMaxBoundValue(value, dstInt)
					maxBoundChecked = maxBoundChecked || newMaxCheck
				}
				if binOp.Op == token.GTR || binOp.Op == token.GEQ {
					newMinCheck := checkMinBoundValue(value, dstInt)
					minBoundChecked = minBoundChecked || newMinCheck
				}
			} else {
				if binOp.Op == token.LSS || binOp.Op == token.LEQ {
					newMinCheck := checkMinBoundValue(value, dstInt)
					minBoundChecked = minBoundChecked || newMinCheck
				}
				if binOp.Op == token.GTR || binOp.Op == token.GEQ {
					newMaxCheck := checkMaxBoundValue(value, dstInt)
					maxBoundChecked = maxBoundChecked || newMaxCheck
				}
			}
		}
	}

	return minBoundChecked, maxBoundChecked
}

type integer struct {
	signed bool
	size   int
}

func parseIntType(intType string) (integer, error) {
	re := regexp.MustCompile(`(?P<type>u?int)(?P<size>\d{1,2})?`)
	matches := re.FindStringSubmatch(intType)
	if matches == nil {
		return integer{}, fmt.Errorf("no integer type match found for %s", intType)
	}

	it := matches[re.SubexpIndex("type")]
	is := matches[re.SubexpIndex("size")]

	signed := false
	if it == "int" {
		signed = true
	}

	// use default system int type in case size is not present in the type
	intSize := strconv.IntSize
	if is != "" {
		var err error
		intSize, err = strconv.Atoi(is)
		if err != nil {
			return integer{}, fmt.Errorf("failed to parse the integer type size: %w", err)
		}
	}

	return integer{signed: signed, size: intSize}, nil
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

	// converting uint to int of the same size or smaller might lead to overflow
	if !srcInt.signed && dstInt.signed && dstInt.size <= srcInt.size {
		return true
	}
	// converting uint to unit of a smaller size might lead to overflow
	if !srcInt.signed && !dstInt.signed && dstInt.size < srcInt.size {
		return true
	}
	// converting int to int of a smaller size might lead to overflow
	if srcInt.signed && dstInt.signed && dstInt.size < srcInt.size {
		return true
	}
	// converting int to uint of a smaller size might lead to overflow
	if srcInt.signed && !dstInt.signed && dstInt.size < srcInt.size && srcInt.size-dstInt.size > 8 {
		return true
	}

	return false
}

func isBoundCheck(binOp *ssa.BinOp, x ssa.Value) bool {
	return (binOp.X == x || binOp.Y == x) &&
		(binOp.Op == token.LSS || binOp.Op == token.LEQ || binOp.Op == token.GTR || binOp.Op == token.GEQ)
}

func constFromBoundCheck(binOp *ssa.BinOp) (constant *ssa.Const, isOnLeft bool) {
	if c, ok := binOp.X.(*ssa.Const); ok {
		return c, true
	}
	if c, ok := binOp.Y.(*ssa.Const); ok {
		return c, false
	}
	return nil, false
}

func checkSourceMinBound(srcInt, dstInt integer) bool {
	if !srcInt.signed {
		// For unsigned types, the minimum bound is always 0 and is always safe
		return true
	}

	if dstInt.signed {
		// Source and destination are both signed
		return -(1 << (srcInt.size - 1)) >= -(1 << (dstInt.size - 1))
	} else {
		// Source is signed and destination is unsigned
		return -(1 << (srcInt.size - 1)) >= 0
	}
}

func checkSourceMaxBound(srcInt, dstInt integer) bool {
	if dstInt.signed {
		if srcInt.signed {
			// Source and destination are both signed
			return (1<<(srcInt.size-1))-1 <= (1<<(dstInt.size-1))-1
		}
		// Source is unsigned and destination is signed
		var a uint = (1 << srcInt.size) - 1
		var b uint = (1 << (dstInt.size - 1)) - 1
		return a <= b
	}
	// Destination is unsigned
	if srcInt.signed {
		// Source is signed and destination is unsigned
		var a uint = (1 << (srcInt.size - 1)) - 1
		var b uint = (1 << dstInt.size) - 1
		return a <= b
	}
	// Both source and destination are unsigned
	return (1<<srcInt.size)-1 <= (1<<dstInt.size)-1
}

func checkMinBoundValue(value int64, dstInt integer) bool {
	if dstInt.signed {
		return value >= -(1 << (dstInt.size - 1))
	}
	return value >= 0 // For unsigned types, the minimum bound is always 0
}

func checkMaxBoundValue(value int64, dstInt integer) bool {
	if dstInt.signed {
		return value <= (1<<(dstInt.size-1))-1
	}
	return value <= (1<<dstInt.size)-1
}
