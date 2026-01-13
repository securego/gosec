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

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

// newConversionOverflowAnalyzer creates a new analysis.Analyzer for detecting integer overflows in conversions.
func newConversionOverflowAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runConversionOverflow,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

type overflowState struct {
	pass       *analysis.Pass
	analyzer   *RangeAnalyzer
	visitedMap map[ssa.Value]bool
}

func newOverflowState(pass *analysis.Pass) *overflowState {
	return &overflowState{
		pass:       pass,
		analyzer:   NewRangeAnalyzer(),
		visitedMap: make(map[ssa.Value]bool),
	}
}

// runConversionOverflow analyzes the SSA representation of the code to find potential integer overflows in type conversions.
func runConversionOverflow(pass *analysis.Pass) (any, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, fmt.Errorf("building ssa representation: %w", err)
	}

	state := newOverflowState(pass)
	issues := []*issue.Issue{}
	for _, mcall := range ssaResult.SSA.SrcFuncs {
		state.analyzer.ResetCache()
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				switch instr := instr.(type) {
				case *ssa.Convert:
					src := instr.X.Type().Underlying().String()
					dst := instr.Type().Underlying().String()
					if isIntOverflow(src, dst) {
						if state.isSafeConversion(instr) {
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

// isIntOverflow checks if a conversion from src type to dst type can theoretically overflow (e.g., int64 -> int8).
func isIntOverflow(src string, dst string) bool {
	srcInt, err := ParseIntType(src)
	if err != nil {
		return false
	}

	dstInt, err := ParseIntType(dst)
	if err != nil {
		return false
	}

	return srcInt.Min < dstInt.Min || srcInt.Max > dstInt.Max
}

// isSafeConversion checks if a specific conversion instruction is safe from overflow, considering logic and constraints.
func (s *overflowState) isSafeConversion(instr *ssa.Convert) bool {
	dstType := instr.Type().Underlying().String()

	// Check for constant conversions.
	if constVal, ok := instr.X.(*ssa.Const); ok {
		if isConstantInRange(constVal, dstType) {
			return true
		}
	}

	// Check for explicit range checks.
	if s.hasRangeCheck(instr.X, instr.Type().Underlying().String(), instr.Block()) {
		return true
	}
	return false
}

// hasRangeCheck determines if there is a valid range check for the given value that ensures safety.
func (s *overflowState) hasRangeCheck(v ssa.Value, dstType string, block *ssa.BasicBlock) bool {
	dstInt, err := ParseIntType(dstType)
	if err != nil {
		return false
	}

	// Clear visited map for new resolution
	clear(s.visitedMap)

	res := s.analyzer.ResolveRange(v, block)
	defer s.analyzer.releaseResult(res)

	// Check for explicit values
	if ExplicitValsInRange(res.explicitPositiveVals, res.explicitNegativeVals, dstInt) {
		return true
	}

	// Check all predecessors for OR support.
	if len(block.Preds) > 1 {
		allPredsSafe := true
		for _, pred := range block.Preds {
			if !s.isSafeFromPredecessor(v, dstType, pred, block) {
				allPredsSafe = false
				break
			}
		}
		if allPredsSafe {
			return true
		}
	}

	// Relax requirement: If we have a definitive range (both set) and it's safe,
	// we allow it even if not explicitly "checked" by an IF,
	// because definition-based ranges (like constants or arithmetic on constants) are certain.
	isDefinitiveSafe := res.minValueSet && res.maxValueSet

	if !res.isRangeCheck && !isDefinitiveSafe {
		return false
	}

	return s.validateRangeLimits(v, res, dstInt)
}

func (s *overflowState) validateRangeLimits(v ssa.Value, res *rangeResult, dstInt IntTypeInfo) bool {
	minValue, minValueSet, maxValue, maxValueSet := res.minValue, res.minValueSet, res.maxValue, res.maxValueSet
	isSrcUnsigned := isUint(v)

	// Check for impossible ranges (disjoint)
	if !isSrcUnsigned {
		if minValueSet && maxValueSet && toInt64(minValue) > toInt64(maxValue) {
			return true
		}
	}
	if isSrcUnsigned && minValueSet && maxValueSet && minValue > maxValue {
		return true
	}

	srcInt, err := ParseIntType(v.Type().Underlying().String())
	if err != nil {
		return false
	}

	if dstInt.Signed {
		if isSrcUnsigned {
			return maxValueSet && maxValue <= uint64(dstInt.Max)
		}
		minSafe := true
		if srcInt.Min < dstInt.Min {
			minSafe = minValueSet && toInt64(minValue) >= int64(dstInt.Min)
		}
		maxSafe := true
		if srcInt.Max > dstInt.Max {
			maxSafe = maxValueSet && toInt64(maxValue) <= toInt64(uint64(dstInt.Max))
		}
		return minSafe && maxSafe
	}
	if isSrcUnsigned {
		return maxValueSet && maxValue <= uint64(dstInt.Max)
	}
	minSafe := true
	if srcInt.Min < 0 {
		minSafe = minValueSet && toInt64(minValue) >= 0
	}
	maxSafe := true
	if uint64(srcInt.Max) > uint64(dstInt.Max) {
		maxSafe = maxValueSet && maxValue <= uint64(dstInt.Max)
	}
	return minSafe && maxSafe
}

func (s *overflowState) isSafeFromPredecessor(v ssa.Value, dstType string, pred *ssa.BasicBlock, targetBlock *ssa.BasicBlock) bool {
	if vIf, ok := pred.Instrs[len(pred.Instrs)-1].(*ssa.If); ok {
		dstInt, _ := ParseIntType(dstType)
		isSrcUnsigned := isUint(v)
		for i, succ := range pred.Succs {
			if succ == targetBlock {
				// We took this specific edge.
				result := s.analyzer.getResultRangeForIfEdge(vIf, i == 0, v)
				defer s.analyzer.releaseResult(result)

				if result.isRangeCheck {
					var safe bool
					if dstInt.Signed {
						if isSrcUnsigned {
							safe = result.maxValueSet && result.maxValue <= uint64(dstInt.Max)
						} else {
							safe = (result.minValueSet && toInt64(result.minValue) >= int64(dstInt.Min)) && (result.maxValueSet && toInt64(result.maxValue) <= toInt64(uint64(dstInt.Max)))
						}
					} else {
						if isSrcUnsigned {
							safe = result.maxValueSet && result.maxValue <= uint64(dstInt.Max)
						} else {
							safe = (result.minValueSet && toInt64(result.minValue) >= 0) && (result.maxValueSet && result.maxValue <= uint64(dstInt.Max))
						}
					}
					if safe {
						return true
					}
				}
			}
		}
	}
	return false
}
