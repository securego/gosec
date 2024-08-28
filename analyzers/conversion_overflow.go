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
	block := instr.Block()
	dstInt, err := parseIntType(dstType)
	if err != nil {
		return false
	}

	minBoundChecked := false
	maxBoundChecked := false

	srcInt, err := parseIntType(instr.X.Type().String())
	if err != nil {
		return false
	}

	minBoundChecked = checkSourceMinBound(srcInt, dstInt)
	maxBoundChecked = checkSourceMaxBound(srcInt, dstInt)

	// If both bounds are already checked, return true
	if minBoundChecked && maxBoundChecked {
		return true
	}

	// Recursive function to check predecessors
	var checkPredecessors func(block *ssa.BasicBlock) bool
	checkPredecessors = func(block *ssa.BasicBlock) bool {
		for _, pred := range block.Preds {
			minChecked, maxChecked := checkBlockForRangeCheck(pred, instr, dstInt)
			if minChecked {
				minBoundChecked = true
			}
			if maxChecked {
				maxBoundChecked = true
			}
			if minBoundChecked && maxBoundChecked {
				return true
			}
			if checkPredecessors(pred) {
				return true
			}
		}
		return false
	}

	// Start checking from the initial block
	checkPredecessors(block)

	if minBoundChecked && maxBoundChecked {
		return true
	}

	return false
}

func checkBlockForRangeCheck(block *ssa.BasicBlock, instr *ssa.Convert, dstInt integer) (bool, bool) {
	minBoundChecked := false
	maxBoundChecked := false

	for _, i := range block.Instrs {
		if binOp, ok := i.(*ssa.BinOp); ok && isRelevantBinOp(binOp, instr.X) {
			constVal := extractConst(binOp)
			if constVal == nil {
				continue
			}

			value, err := strconv.ParseInt(constVal.Value.String(), 10, 64)
			if err != nil {
				continue
			}

			minBoundChecked = minBoundChecked || checkMinBoundValue(value, dstInt)
			maxBoundChecked = maxBoundChecked || checkMaxBoundValue(value, dstInt)

			if minBoundChecked && maxBoundChecked {
				break
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

func isRelevantBinOp(binOp *ssa.BinOp, x ssa.Value) bool {
	return (binOp.X == x || binOp.Y == x) &&
		(binOp.Op == token.LSS || binOp.Op == token.LEQ || binOp.Op == token.GTR || binOp.Op == token.GEQ)
}

func extractConst(binOp *ssa.BinOp) *ssa.Const {
	if c, ok := binOp.Y.(*ssa.Const); ok {
		return c
	}
	if c, ok := binOp.X.(*ssa.Const); ok {
		return c
	}
	return nil
}

func checkSourceMinBound(srcInt, dstInt integer) bool {
	if dstInt.signed {
		if srcInt.signed {
			// Source and destination are both signed
			return -(1 << (srcInt.size - 1)) >= -(1 << (dstInt.size - 1))
		}
		// Source is unsigned and destination is signed
		return 0 >= -(1 << (dstInt.size - 1))
	}
	if srcInt.signed {
		// Source is signed and destination is unsigned
		return -(1 << (srcInt.size - 1)) >= 0
	}
	// Both source and destination are unsigned
	return true
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
		return value == -(1 << (dstInt.size - 1))
	}
	return value >= 0 // For unsigned types, the minimum bound is always 0
}

func checkMaxBoundValue(value int64, dstInt integer) bool {
	if dstInt.signed {
		return value == (1<<(dstInt.size-1))-1
	}
	return value == (1<<dstInt.size)-1
}
