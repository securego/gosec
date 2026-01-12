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
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

type rangeResult struct {
	minValue             uint64
	maxValue             uint64
	minValueSet          bool
	maxValueSet          bool
	explicitPositiveVals []uint
	explicitNegativeVals []int
	isRangeCheck         bool
}

const (
	minInt64  = int64(math.MinInt64)
	maxUint64 = uint64(math.MaxUint64)
	maxInt64  = uint64(math.MaxInt64)
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
	rangeCache map[rangeCacheKey]rangeResult
}

type rangeCacheKey struct {
	block *ssa.BasicBlock
	val   ssa.Value
}

func newOverflowState(pass *analysis.Pass) *overflowState {
	return &overflowState{
		pass:       pass,
		rangeCache: make(map[rangeCacheKey]rangeResult),
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

type operationInfo struct {
	op      string
	extra   ssa.Value
	flipped bool
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
	if s.hasRangeCheck(instr.X, dstType, instr.Block()) {
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

	isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")

	res := s.resolveRange(v, block, make(map[ssa.Value]bool))
	minValue, minValueSet, maxValue, maxValueSet, isRangeCheck := res.minValue, res.minValueSet, res.maxValue, res.maxValueSet, res.isRangeCheck
	explicitPositiveVals, explicitNegativeVals := res.explicitPositiveVals, res.explicitNegativeVals
	if explicitValsInRange(explicitPositiveVals, explicitNegativeVals, dstInt) {
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

	if explicitValsInRange(res.explicitPositiveVals, res.explicitNegativeVals, dstInt) {
		return true
	}

	// Relax requirement: If we have a definitive range (both set) and it's safe,
	// we allow it even if not explicitly "checked" by an IF,
	// because definition-based ranges (like constants or arithmetic on constants) are certain.
	isDefinitiveSafe := minValueSet && maxValueSet

	if !isRangeCheck && !isDefinitiveSafe {
		return false
	}

	// Check for impossible ranges (disjoint)
	if !isSrcUnsigned {
		if minValueSet && maxValueSet && toInt64(minValue) > toInt64(maxValue) {
			return true
		}
	}
	if isSrcUnsigned && minValueSet && maxValueSet && minValue > maxValue {
		return true
	}

	if dstInt.Signed {
		if isSrcUnsigned {
			return maxValueSet && maxValue <= uint64(dstInt.Max)
		}
		return (minValueSet && toInt64(minValue) >= int64(dstInt.Min)) && (maxValueSet && toInt64(maxValue) <= toInt64(uint64(dstInt.Max)))
	}
	if isSrcUnsigned {
		return maxValueSet && maxValue <= uint64(dstInt.Max)
	}
	return (minValueSet && toInt64(minValue) >= 0) && (maxValueSet && maxValue <= uint64(dstInt.Max))
}

// minBounds computes the minimum of two uint64 values, treating them as signed if !isSrcUnsigned.
func minBounds(a, b uint64, isSrcUnsigned bool) uint64 {
	if !isSrcUnsigned {
		if toInt64(a) < toInt64(b) {
			return a
		}
		return b
	}
	if a < b {
		return a
	}
	return b
}

// updateRangeMinMax updates the min or max value of the result range if the new value is tighter.
func updateRangeMinMax(result *rangeResult, newVal uint64, isMin bool, isSrcUnsigned bool) {
	if isMin {
		if !result.minValueSet || (isSrcUnsigned && newVal > result.minValue) || (!isSrcUnsigned && toInt64(newVal) > toInt64(result.minValue)) {
			result.minValue = newVal
			result.minValueSet = true
			result.isRangeCheck = true
		}
	} else {
		if !result.maxValueSet || (isSrcUnsigned && newVal < result.maxValue) || (!isSrcUnsigned && toInt64(newVal) < toInt64(result.maxValue)) {
			result.maxValue = newVal
			result.maxValueSet = true
			result.isRangeCheck = true
		}
	}
}

// maxBounds computes the maximum of two uint64 values, treating them as signed if !isSrcUnsigned.
func maxBounds(a, b uint64, isSrcUnsigned bool) uint64 {
	if a == toUint64(minInt64) { // Using MinInt64 as "not set" for signed-capable minValue
		return b
	}
	if b == toUint64(minInt64) {
		return a
	}
	if !isSrcUnsigned {
		if toInt64(a) > toInt64(b) {
			return a
		}
		return b
	}
	if a > b {
		return a
	}
	return b
}

func (s *overflowState) isSafeFromPredecessor(v ssa.Value, dstType string, pred *ssa.BasicBlock, targetBlock *ssa.BasicBlock) bool {
	if vIf, ok := pred.Instrs[len(pred.Instrs)-1].(*ssa.If); ok {
		dstInt, _ := ParseIntType(dstType)
		isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")
		for i, succ := range pred.Succs {
			if succ == targetBlock {
				// We took this specific edge.
				result := s.getResultRangeForIfEdge(vIf, i == 0, v)
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

// getResultRangeForIfEdge returns the range constraints implied by taking a specific branch (then/else) of an If instruction.
func (s *overflowState) getResultRangeForIfEdge(vIf *ssa.If, isTrue bool, v ssa.Value) rangeResult {
	vCond := vIf.Cond
	res := rangeResult{
		minValue: toUint64(minInt64),
		maxValue: maxUint64,
	}

	if binOp, ok := vCond.(*ssa.BinOp); ok {
		if isRangeCheck(binOp, v) {
			res.isRangeCheck = true
			s.updateResultFromBinOpForValue(&res, binOp, v, isTrue)
		}
	}
	return res
}

// getResultRangeForValue calculates the range of a value by analyzing the dominator tree and control flow.
func (s *overflowState) getResultRangeForValue(ifInstr *ssa.If, v ssa.Value, targetBlock *ssa.BasicBlock) rangeResult {
	cond := ifInstr.Cond
	binOp, ok := cond.(*ssa.BinOp)
	if !ok || !isRangeCheck(binOp, v) {
		return rangeResult{
			minValue: toUint64(minInt64),
			maxValue: maxUint64,
		}
	}

	result := rangeResult{
		minValue:     toUint64(minInt64),
		maxValue:     maxUint64,
		isRangeCheck: true,
	}

	// Determine if targetBlock is reached through then or else branch
	thenFound := isReachable(ifInstr.Block().Succs[0], targetBlock, make(map[*ssa.BasicBlock]bool))
	elseFound := isReachable(ifInstr.Block().Succs[1], targetBlock, make(map[*ssa.BasicBlock]bool))

	if thenFound && elseFound {
		return result
	}

	s.updateResultFromBinOpForValue(&result, binOp, v, thenFound)

	return result
}

// isReachable checks if there is a path from the start block to the target block.
func isReachable(start, target *ssa.BasicBlock, visited map[*ssa.BasicBlock]bool) bool {
	if start == target {
		return true
	}
	if visited[start] {
		return false
	}
	visited[start] = true
	for _, succ := range start.Succs {
		if isReachable(succ, target, visited) {
			return true
		}
	}
	return false
}

// updateResultFromBinOpForValue refines the range result based on a binary operation constraint from a conditional.
func (s *overflowState) updateResultFromBinOpForValue(result *rangeResult, binOp *ssa.BinOp, v ssa.Value, successPathConvert bool) {
	operandsFlipped := false
	compareVal, op := getRealValueFromOperation(v)
	if fieldAddr, ok := compareVal.(*ssa.FieldAddr); ok {
		compareVal = fieldAddr
	}

	var matchSide ssa.Value
	var inverseOp operationInfo
	if isEquivalent(binOp.X, v) {
		matchSide = binOp.Y
		op = operationInfo{}
	} else if isEquivalent(binOp.Y, v) {
		matchSide = binOp.X
		operandsFlipped = true
		op = operationInfo{}
	} else if isSameOrRelated(binOp.X, compareVal) {
		matchSide = binOp.Y
		// check if binOp.X has an operation relative to compareVal
		if rVal, rOp := getRealValueFromOperation(binOp.X); rVal == compareVal {
			inverseOp = rOp
		}
	} else if rVal, rOp := getRealValueFromOperation(binOp.X); rVal == compareVal {
		matchSide = binOp.Y
		inverseOp = rOp
	} else if isSameOrRelated(binOp.Y, compareVal) {
		matchSide = binOp.X
		operandsFlipped = true
		// check if binOp.Y has an operation relative to compareVal
		if rVal, rOp := getRealValueFromOperation(binOp.Y); rVal == compareVal {
			inverseOp = rOp
		}
	} else if rVal, rOp := getRealValueFromOperation(binOp.Y); rVal == compareVal {
		matchSide = binOp.X
		operandsFlipped = true
		inverseOp = rOp
	} else {
		return
	}

	val, ok := GetConstantInt64(matchSide)

	if !ok {
		return
	}

	// Apply inverse operations to the limit 'val' before updating min/max
	// e.g. if x << 2 < 100. val=100. inverseOp=<<.
	// we want range for x. x < 100 >> 2.
	if inverseOp.op != "" {
		switch inverseOp.op {
		case "<<":
			if vShift, ok := GetConstantInt64(inverseOp.extra); ok && vShift >= 0 {
				val = val >> uint(vShift)
			}
		case "+":
			if vAdd, ok := GetConstantInt64(inverseOp.extra); ok {
				val -= vAdd
			}
		case "-":
			if vSub, ok := GetConstantInt64(inverseOp.extra); ok {
				if inverseOp.flipped { // val = extra - x => x = extra - val
					val = vSub - val
					operandsFlipped = !operandsFlipped
				} else { // val = x - extra => x = val + extra
					val += vSub
				}
			}
		case ">>":
			if vShift, ok := GetConstantInt64(inverseOp.extra); ok && vShift >= 0 {
				val = val << uint(vShift)
			}
		case "*":
			if vMul, ok := GetConstantUint64(inverseOp.extra); ok && vMul > 0 {
				val = toInt64(toUint64(val) / vMul)
			}
		case "/":
			if vQuo, ok := GetConstantUint64(inverseOp.extra); ok && vQuo > 0 {
				if inverseOp.flipped { // val = extra / x => x = extra / val
					if val != 0 {
						val = toInt64(vQuo / toUint64(val))
					}
					operandsFlipped = !operandsFlipped
				} else { // val = x / extra => x = val * vQuo
					val = toInt64(toUint64(val) * vQuo)
				}
			}
		}
	}

	// Apply forward operations from 'op' to the limit 'val'
	// e.g. if x < 30 and v is x * 10. val=30. op=*.
	// we want range for v. v < 30 * 10.
	if op.op != "" {
		switch op.op {
		case "<<":
			if vShift, ok := GetConstantInt64(op.extra); ok && vShift >= 0 {
				val = val << uint(vShift)
			}
		case "+":
			if vAdd, ok := GetConstantInt64(op.extra); ok {
				val += vAdd
			}
		case "-":
			if vSub, ok := GetConstantInt64(op.extra); ok {
				if op.flipped { // v = extra - x. x < val => v > extra - val
					val = vSub - val
					operandsFlipped = !operandsFlipped
				} else { // v = x - extra. x < val => v < val - extra
					val -= vSub
				}
			}
		case ">>":
			if vShift, ok := GetConstantInt64(op.extra); ok && vShift >= 0 {
				val = val >> uint(vShift)
			}
		case "*":
			isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")
			if isSrcUnsigned {
				if vMul, ok := GetConstantUint64(op.extra); ok && vMul != 0 {
					hi, lo := bits.Mul64(toUint64(val), vMul)
					if hi != 0 {
						return
					}
					val = toInt64(lo)
				}
			} else {
				if vMul, ok := GetConstantInt64(op.extra); ok && vMul != 0 {
					if vMul > 0 {
						if val >= 0 {
							hi, lo := bits.Mul64(toUint64(val), uint64(vMul))
							if hi != 0 {
								return
							}
							val = toInt64(lo)
						} else {
							// Negative val, positive vMul
							if val < minInt64/vMul {
								return
							}
							val = val * vMul
						}
					} else {
						// Negative vMul
						val = val * vMul
						operandsFlipped = !operandsFlipped
					}
				}
			}
		case "/":
			if vQuo, ok := GetConstantInt64(op.extra); ok && vQuo > 0 {
				if op.flipped { // v = extra / x. x < val => v > extra / val
					if val != 0 {
						val = vQuo / val
					}
					operandsFlipped = !operandsFlipped
				} else { // v = x / extra. x < val => v < val / vQuo
					val = val / vQuo
				}
			}
		case "neg":
			val = -val
			operandsFlipped = !operandsFlipped
		}
	}

	switch binOp.Op {
	case token.LEQ, token.LSS:
		updateMinMaxForLessOrEqual(result, val, binOp.Op, operandsFlipped, successPathConvert)
	case token.GEQ, token.GTR:
		updateMinMaxForGreaterOrEqual(result, val, binOp.Op, operandsFlipped, successPathConvert)
	case token.EQL:
		if successPathConvert {
			updateExplicitValues(result, val)
		}
	case token.NEQ:
		if !successPathConvert {
			updateExplicitValues(result, val)
		}
	}

	switch op.op {
	case "neg":
		oldMinSet, oldMaxSet := result.minValueSet, result.maxValueSet
		oldMin, oldMax := result.minValue, result.maxValue
		result.minValueSet, result.maxValueSet = false, false
		if oldMinSet {
			result.maxValue = toUint64(-toInt64(oldMin))
			result.maxValueSet = true
		}
		if oldMaxSet {
			result.minValue = toUint64(-toInt64(oldMax))
			result.minValueSet = true
		}
	case "+":
		if val, ok := GetConstantInt64(op.extra); ok {
			if result.minValueSet {
				result.minValue = toUint64(toInt64(result.minValue) + val)
			}
			if result.maxValueSet {
				result.maxValue = toUint64(toInt64(result.maxValue) + val)
			}
		}
	case "-":
		if val, ok := GetConstantInt64(op.extra); ok {
			if op.flipped {
				oldMinSet, oldMaxSet := result.minValueSet, result.maxValueSet
				oldMin, oldMax := result.minValue, result.maxValue
				result.minValueSet, result.maxValueSet = false, false
				if oldMaxSet {
					result.minValue = toUint64(val - toInt64(oldMax))
					result.minValueSet = true
				}
				if oldMinSet {
					result.maxValue = toUint64(val - toInt64(oldMin))
					result.maxValueSet = true
				}
			} else {
				if result.minValueSet {
					result.minValue = toUint64(toInt64(result.minValue) - val)
				}
				if result.maxValueSet {
					result.maxValue = toUint64(toInt64(result.maxValue) - val)
				}
			}
		}
	case "&":
		if val, ok := GetConstantInt64(op.extra); ok && val >= 0 {
			result.minValue = 0
			result.minValueSet = true
			result.maxValue = uint64(val)
			result.maxValueSet = true
		}
	case ">>":
		if val, ok := GetConstantInt64(op.extra); ok && val >= 0 {
			if result.maxValueSet {
				result.maxValue >>= uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
			}
		}
	case "<<":
		if val, ok := GetConstantInt64(op.extra); ok && val >= 0 {
			if result.maxValueSet {
				result.maxValue <<= uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
			}
			if result.minValueSet {
				result.minValue <<= uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
			}
		}
	case "%":
		if val, ok := GetConstantInt64(op.extra); ok && val > 0 {
			if (result.minValueSet && toInt64(result.minValue) >= 0) || isNonNegative(binOp.X) || isNonNegative(compareVal) {
				result.minValue = 0
				result.minValueSet = true
				result.maxValue = uint64(val - 1) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
				result.maxValueSet = true
			} else {
				//-(val-1)
				// Need to cast carefully: uint64(int64(...))
				negVal := -(val - 1)
				result.minValue = toUint64(negVal)
				result.minValueSet = true
				result.maxValue = uint64(val - 1) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
				result.maxValueSet = true
			}
		}
	}
}

// computeRange calculates the range of a value based on its definition (arithmetic operations, constants).
func (s *overflowState) computeRange(v ssa.Value, block *ssa.BasicBlock, visited map[ssa.Value]bool) rangeResult {
	if visited[v] {
		return rangeResult{}
	}
	visited[v] = true
	defer delete(visited, v)

	res := rangeResult{}
	isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")

	if isNonNegative(v) {
		res.minValue = 0
		res.minValueSet = true
	}

	// Definition-based range
	switch v := v.(type) {
	case *ssa.BinOp:
		switch v.Op {
		case token.ADD:
			subResX := s.resolveRange(v.X, block, visited)
			subResY := s.resolveRange(v.Y, block, visited)
			if subResX.minValueSet && subResY.minValueSet {
				res.minValue = toUint64(toInt64(subResX.minValue) + toInt64(subResY.minValue))
				res.minValueSet = true
			}
			if subResX.maxValueSet && subResY.maxValueSet {
				res.maxValue = toUint64(toInt64(subResX.maxValue) + toInt64(subResY.maxValue))
				res.maxValueSet = true
			}
			res.isRangeCheck = subResX.isRangeCheck || subResY.isRangeCheck
		case token.SUB:
			subResX := s.resolveRange(v.X, block, visited)
			if val, ok := GetConstantInt64(v.Y); ok {
				// x - val
				if subResX.minValueSet {
					res.minValue = toUint64(toInt64(subResX.minValue) - val)
					res.minValueSet = true
				}
				if subResX.maxValueSet {
					res.maxValue = toUint64(toInt64(subResX.maxValue) - val)
					res.maxValueSet = true
				}
				res.isRangeCheck = subResX.isRangeCheck
			} else if val, ok := GetConstantInt64(v.X); ok {
				// val - x
				subResY := s.resolveRange(v.Y, block, visited)
				if subResY.maxValueSet {
					res.minValue = toUint64(val - toInt64(subResY.maxValue))
					res.minValueSet = true
					res.maxValue = toUint64(val - toInt64(subResY.minValue))
					res.maxValueSet = true
				}
				res.isRangeCheck = subResY.isRangeCheck
			}
		case token.AND:
			// AND decreases magnitude usually.
			if val, ok := GetConstantUint64(v.Y); ok {
				res.minValue = 0
				res.minValueSet = true
				res.maxValue = val
				res.maxValueSet = true
				res.isRangeCheck = true
			} else {
				// If Y is not a constant, we can only say it's non-negative if X is.
				if isNonNegative(v.X) {
					res.minValue = 0
					res.minValueSet = true
				}
			}
		case token.SHR:
			if val, ok := GetConstantInt64(v.Y); ok && val >= 0 {
				subResX := s.resolveRange(v.X, block, visited)
				if isNonNegative(v.X) {
					res.minValue = 0
					res.minValueSet = true
				}
				if subResX.maxValueSet {
					res.maxValue = subResX.maxValue >> uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					res.maxValueSet = true
				} else if typeInt, err := ParseIntType(v.X.Type().Underlying().String()); err == nil {
					// Fallback to type max
					res.maxValue = uint64(typeInt.Max) >> uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					res.maxValueSet = true
				}
				res.isRangeCheck = subResX.isRangeCheck
			}
		case token.SHL:
			if val, ok := GetConstantInt64(v.Y); ok && val >= 0 {
				subResX := s.resolveRange(v.X, block, visited)
				if subResX.minValueSet {
					newMin := subResX.minValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					// Check for overflow/wrap-around
					// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					if newMin>>uint(val) == subResX.minValue {
						res.minValue = newMin
						res.minValueSet = true
					}
				}
				if subResX.maxValueSet {
					newMax := subResX.maxValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					// Check for overflow/wrap-around
					// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					if newMax>>uint(val) == subResX.maxValue {
						res.maxValue = newMax
						res.maxValueSet = true
					}
				}
				res.isRangeCheck = subResX.isRangeCheck
			}
		case token.REM:
			if val, ok := GetConstantInt64(v.Y); ok && val > 0 {
				subResX := s.resolveRange(v.X, block, visited)
				if (subResX.minValueSet && toInt64(subResX.minValue) >= 0) || isNonNegative(v.X) {
					res.minValue = 0
					res.minValueSet = true
					res.maxValue = uint64(val - 1) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					res.maxValueSet = true
				} else {
					res.minValue = toUint64(-(val - 1))
					res.minValueSet = true
					res.maxValue = uint64(val - 1) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					res.maxValueSet = true
				}
				res.isRangeCheck = true
			}
		case token.MUL:
			val, ok := GetConstantUint64(v.Y)
			if !ok {
				val, ok = GetConstantUint64(v.X)
			}
			if ok && val != 0 {
				var subRes rangeResult
				if isSameOrRelated(v.Y, v.X) {
					// x*x handled by generic fallback
				} else if _, isConst := v.Y.(*ssa.Const); isConst {
					subRes = s.resolveRange(v.X, block, visited)
				} else {
					subRes = s.resolveRange(v.Y, block, visited)
				}

				if subRes.maxValueSet {
					hi, _ := bits.Mul64(subRes.maxValue, val)
					if hi != 0 {
						return res
					}
				}

				if subRes.minValueSet {
					res.minValue = subRes.minValue * val
					res.minValueSet = true
				}
				if subRes.maxValueSet {
					res.maxValue = subRes.maxValue * val
					res.maxValueSet = true
				}
				res.isRangeCheck = subRes.isRangeCheck
			}
		case token.QUO:
			if val, ok := GetConstantUint64(v.Y); ok && val != 0 {
				subResX := s.resolveRange(v.X, block, visited)
				isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")
				if isSrcUnsigned {
					if subResX.minValueSet {
						res.minValue = subResX.minValue / val
						res.minValueSet = true
					}
					if subResX.maxValueSet {
						res.maxValue = subResX.maxValue / val
						res.maxValueSet = true
					}
				} else {
					vVal := toInt64(val)
					if vVal > 0 {
						if subResX.minValueSet {
							res.minValue = toUint64(toInt64(subResX.minValue) / vVal)
							res.minValueSet = true
						}
						if subResX.maxValueSet {
							res.maxValue = toUint64(toInt64(subResX.maxValue) / vVal)
							res.maxValueSet = true
						}
					} else { // vVal < 0
						if subResX.maxValueSet {
							res.minValue = toUint64(toInt64(subResX.maxValue) / vVal)
							res.minValueSet = true
						}
						if subResX.minValueSet {
							res.maxValue = toUint64(toInt64(subResX.minValue) / vVal)
							res.maxValueSet = true
						}
					}
				}
				res.isRangeCheck = subResX.isRangeCheck
			}
		}
	case *ssa.UnOp:
		subRes := s.resolveRange(v.X, block, visited)
		switch v.Op {
		case token.SUB:
			// Negation: -x.
			// Min = -Max. Max = -Min.
			if subRes.maxValueSet {
				res.minValue = toUint64(-toInt64(subRes.maxValue))
				res.minValueSet = true
			}
			if subRes.minValueSet {
				res.maxValue = toUint64(-toInt64(subRes.minValue))
				res.maxValueSet = true
			}
			res.isRangeCheck = subRes.isRangeCheck
		case token.XOR:
			// Bitwise NOT: ^x = -x - 1.
			// Min = ^Max. Max = ^Min.
			if subRes.maxValueSet {
				res.minValue = toUint64(toInt64(^subRes.maxValue))
				res.minValueSet = true
			}
			if subRes.minValueSet {
				res.maxValue = toUint64(toInt64(^subRes.minValue))
				res.maxValueSet = true
			}
			res.isRangeCheck = subRes.isRangeCheck
		}
	case *ssa.Call:
		if fn, ok := v.Call.Value.(*ssa.Builtin); ok {
			switch fn.Name() {
			case "len", "cap":
				if len(v.Call.Args) == 1 {
					arg := v.Call.Args[0]
					if _, ok := arg.(*ssa.Slice); ok || arg.Type().String() == "string" {
						// len(slice) or len(string) is non-negative
						// Try to resolve range of the slice/string length if possible?
						// For now, just >= 0.
						// We can also check if the slice came from make()
						argRes := s.resolveRange(arg, block, visited)
						if argRes.minValueSet {
							res.minValue = argRes.minValue
							res.minValueSet = true
						} else {
							res.minValue = 0
							res.minValueSet = true
						}
						if argRes.maxValueSet {
							res.maxValue = argRes.maxValue
							res.maxValueSet = true
						}
						res.isRangeCheck = true
					}
				}
			case "min":
				for i, arg := range v.Call.Args {
					argRes := s.resolveRange(arg, block, visited)
					if i == 0 {
						res.minValue = argRes.minValue
						res.maxValue = argRes.maxValue
						res.minValueSet = argRes.minValueSet
						res.maxValueSet = argRes.maxValueSet
						continue
					}
					if argRes.minValueSet {
						if !res.minValueSet {
							res.minValue = argRes.minValue
							res.minValueSet = true
						} else {
							res.minValue = minBounds(res.minValue, argRes.minValue, isSrcUnsigned)
						}
					}
					if argRes.maxValueSet {
						if !res.maxValueSet {
							res.maxValue = argRes.maxValue
							res.maxValueSet = true
						} else {
							res.maxValue = minBounds(res.maxValue, argRes.maxValue, isSrcUnsigned)
						}
					}
				}
				res.isRangeCheck = true
			case "max":
				for i, arg := range v.Call.Args {
					argRes := s.resolveRange(arg, block, visited)
					if i == 0 {
						res.minValue = argRes.minValue
						res.maxValue = argRes.maxValue
						res.minValueSet = argRes.minValueSet
						res.maxValueSet = argRes.maxValueSet
						continue
					}
					if argRes.minValueSet {
						if !res.minValueSet {
							res.minValue = argRes.minValue
							res.minValueSet = true
						} else {
							res.minValue = maxBounds(res.minValue, argRes.minValue, isSrcUnsigned)
						}
					}
					if argRes.maxValueSet {
						if !res.maxValueSet {
							res.maxValue = argRes.maxValue
							res.maxValueSet = true
						} else {
							res.maxValue = maxBounds(res.maxValue, argRes.maxValue, isSrcUnsigned)
						}
					}
				}
				res.isRangeCheck = true
			}
		}
	case *ssa.Extract:
		if v.Index == 0 {
			if call, ok := v.Tuple.(*ssa.Call); ok {
				if callee := call.Call.StaticCallee(); callee != nil {
					switch callee.Name() {
					case "ParseInt":
						if len(call.Call.Args) == 3 {
							if bitSizeVal, ok := GetConstantInt64(call.Call.Args[2]); ok {
								shift := int(bitSizeVal) - 1
								if shift >= 0 && shift < 64 {
									res.minValue = toUint64(-1 << shift)
									res.maxValue = toUint64((1 << shift) - 1)
									res.minValueSet = true
									res.maxValueSet = true
									res.isRangeCheck = true
								}
							}
						}
					case "ParseUint":
						if len(call.Call.Args) == 3 {
							if bitSizeVal, ok := GetConstantInt64(call.Call.Args[2]); ok {
								if bitSizeVal == 64 {
									res.maxValue = maxUint64
								} else if bitSizeVal > 0 && bitSizeVal < 64 {
									res.maxValue = (1 << bitSizeVal) - 1
								}
								res.minValue = 0
								res.minValueSet = true
								res.maxValueSet = true
								res.isRangeCheck = true
							}
						}
					}
				}
			}
		}
	case *ssa.Convert:
		subRes := s.resolveRange(v.X, block, visited)
		if subRes.minValueSet || subRes.maxValueSet {
			res = subRes
		}
	case *ssa.ChangeType:
		subRes := s.resolveRange(v.X, block, visited)
		if subRes.minValueSet || subRes.maxValueSet {
			res = subRes
		}

	case *ssa.Const:
		if val, ok := GetConstantInt64(v); ok {
			res.minValue = toUint64(val)
			res.maxValue = toUint64(val)
			res.minValueSet = true
			res.maxValueSet = true
			// Constants are effectively range checks themselves (exact values)
			res.isRangeCheck = true
		}
	}

	return res
}

// isConstantInRange checks if a constant value fits within the range of the destination type.
func isConstantInRange(constVal *ssa.Const, dstType string) bool {
	value, err := strconv.ParseInt(constVal.Value.String(), 10, 64)
	if err != nil {
		return false
	}

	dstInt, err := ParseIntType(dstType)
	if err != nil {
		return false
	}

	if dstInt.Signed {
		return value >= -(1<<(dstInt.Size-1)) && value <= (1<<(dstInt.Size-1))-1
	}
	return value >= 0 && value <= (1<<dstInt.Size)-1
}

// getDominators returns a list of dominator blocks for the given block, in order from root to the block.
func getDominators(block *ssa.BasicBlock) []*ssa.BasicBlock {
	var doms []*ssa.BasicBlock
	curr := block
	for curr != nil {
		doms = append(doms, curr)
		curr = curr.Idom()
	}
	// Reverse to get root-to-block order
	for i, j := 0, len(doms)-1; i < j; i, j = i+1, j-1 {
		doms[i], doms[j] = doms[j], doms[i]
	}
	return doms
}

// isNonNegative checks if a value is statically known to be non-negative.
func isNonNegative(v ssa.Value) bool {
	return isNonNegativeRecursive(v, make(map[ssa.Value]bool))
}

func isNonNegativeRecursive(v ssa.Value, visited map[ssa.Value]bool) bool {
	if visited[v] {
		return true // Assume non-negative to break cycles in loop indices
	}
	visited[v] = true

	// Any unsigned type is inherently non-negative.
	if srcType := v.Type().Underlying().String(); strings.HasPrefix(srcType, "uint") {
		return true
	}

	v, info := getRealValueFromOperation(v)
	if info.op == "neg" {
		return false
	}
	switch v := v.(type) {
	case *ssa.Extract:
		if _, ok := v.Tuple.(*ssa.Next); ok {
			return true
		}
	case *ssa.Call:
		if fn, ok := v.Call.Value.(*ssa.Builtin); ok {
			switch fn.Name() {
			case "len", "cap":
				return true
			case "min":
				for _, arg := range v.Call.Args {
					if !isNonNegativeRecursive(arg, visited) {
						return false
					}
				}
				return len(v.Call.Args) > 0
			case "max":
				for _, arg := range v.Call.Args {
					if isNonNegativeRecursive(arg, visited) {
						return true
					}
				}
				return false
			}
		}
		if callee := v.Call.StaticCallee(); callee != nil {
			name := callee.String()
			if strings.Contains(name, "UnixMilli") || strings.Contains(name, "UnixMicro") || strings.Contains(name, "UnixNano") {
				return true
			}
		}
	case *ssa.BinOp:
		switch v.Op {
		case token.ADD, token.MUL, token.QUO:
			// For ADD, MUL, QUO, if both operands are non-negative, result is non-negative.
			return isNonNegativeRecursive(v.X, visited) && isNonNegativeRecursive(v.Y, visited)
		case token.REM, token.AND, token.SHR:
			// For % and &, non-negativity can be derived if X is non-negative.
			return isNonNegativeRecursive(v.X, visited)
		}
	case *ssa.Const:
		if val, ok := GetConstantInt64(v); ok && val >= 0 {
			return true
		}
	case *ssa.Phi:
		// A phi is non-negative if all its incoming edges are non-negative.
		// Special case for loop indices: if it starts at 0 or -1 (and used as +1).
		allNonNeg := true
		for _, edge := range v.Edges {
			if !isNonNegativeRecursive(edge, visited) {
				// Check for -1 constant which is common in loop indices that are then incremented.
				if constVal, ok := edge.(*ssa.Const); ok {
					if val, ok := GetConstantInt64(constVal); ok && val == -1 {
						continue
					}
				}
				allNonNeg = false
				break
			}
		}
		return allNonNeg
	case *ssa.Convert:
		srcType := v.X.Type().Underlying().String()
		if strings.HasPrefix(srcType, "uint") {
			return true
		}
	}
	return false
}

func updateExplicitValues(result *rangeResult, val int64) {
	if val < 0 {
		result.explicitNegativeVals = append(result.explicitNegativeVals, int(val))
	} else {
		result.explicitPositiveVals = append(result.explicitPositiveVals, uint(val))
	}
	result.minValue = toUint64(val)
	result.maxValue = toUint64(val)
	result.minValueSet = true
	result.maxValueSet = true
}

func updateMinMaxForLessOrEqual(result *rangeResult, val int64, op token.Token, operandsFlipped bool, successPathConvert bool) {
	if successPathConvert != operandsFlipped {
		// Path where x < val or x <= val
		result.maxValue = toUint64(val)
		if op == token.LSS {
			result.maxValue--
		}
		result.maxValueSet = true
	} else {
		// Path where x >= val
		result.minValue = toUint64(val)
		if op == token.LEQ {
			result.minValue++ // !(x <= val) -> x > val
		}
		result.minValueSet = true
	}
}

func updateMinMaxForGreaterOrEqual(result *rangeResult, val int64, op token.Token, operandsFlipped bool, successPathConvert bool) {
	if successPathConvert != operandsFlipped {
		// Path where x > val or x >= val
		result.minValue = toUint64(val)
		if op == token.GTR {
			result.minValue++
		}
		result.minValueSet = true
	} else {
		// Path where x < val
		result.maxValue = toUint64(val)
		if op == token.GEQ {
			result.maxValue-- // !(x >= val) -> x < val
		}
		result.maxValueSet = true
	}
}

func isRangeCheck(v ssa.Value, x ssa.Value) bool {
	compareVal, _ := getRealValueFromOperation(x)
	switch op := v.(type) {
	case *ssa.BinOp:
		switch op.Op {
		case token.LSS, token.LEQ, token.GTR, token.GEQ, token.EQL, token.NEQ:
			leftMatch := isSameOrRelated(op.X, x) || isSameOrRelated(op.X, compareVal)
			if !leftMatch {
				if rVal, _ := getRealValueFromOperation(op.X); rVal == x || (compareVal != nil && rVal == compareVal) {
					leftMatch = true
				}
			}
			rightMatch := isSameOrRelated(op.Y, x) || isSameOrRelated(op.Y, compareVal)
			if !rightMatch {
				if rVal, _ := getRealValueFromOperation(op.Y); rVal == x || (compareVal != nil && rVal == compareVal) {
					rightMatch = true
				}
			}
			return leftMatch || rightMatch
		}
	}
	return false
}

func isEquivalent(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	// Handle distinct constant pointers
	if aConst, ok := a.(*ssa.Const); ok {
		if bConst, ok := b.(*ssa.Const); ok {
			return aConst.Value == bConst.Value && aConst.Type() == bConst.Type()
		}
	}

	if aBin, ok := a.(*ssa.BinOp); ok {
		if bBin, ok := b.(*ssa.BinOp); ok {
			return aBin.Op == bBin.Op && isEquivalent(aBin.X, bBin.X) && isEquivalent(aBin.Y, bBin.Y)
		}
	}
	if aUn, ok := a.(*ssa.UnOp); ok {
		if bUn, ok := b.(*ssa.UnOp); ok {
			return aUn.Op == bUn.Op && isEquivalent(aUn.X, bUn.X)
		}
	}
	return false
}

func getRealValueFromOperation(v ssa.Value) (ssa.Value, operationInfo) {
	switch v := v.(type) {
	case *ssa.UnOp:
		if v.Op == token.SUB {
			return v.X, operationInfo{op: "neg"}
		}
		return v, operationInfo{}
	case *ssa.BinOp:
		switch v.Op {
		case token.ADD, token.SUB, token.AND, token.SHR, token.SHL, token.REM, token.MUL, token.QUO:
			if _, ok := v.Y.(*ssa.Const); ok {
				return v.X, operationInfo{op: v.Op.String(), extra: v.Y}
			}
			if _, ok := v.X.(*ssa.Const); ok {
				return v.Y, operationInfo{op: v.Op.String(), extra: v.X, flipped: true}
			}
		}
	case *ssa.FieldAddr:
		return v, operationInfo{op: "field"}
	case *ssa.Alloc:
		return v, operationInfo{op: "alloc"}
	}
	return v, operationInfo{}
}

// isSameOrRelated checks if two SSA values represent the same underlying variable or related struct fields.
func isSameOrRelated(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	if aExt, ok := a.(*ssa.Extract); ok {
		if bExt, ok := b.(*ssa.Extract); ok {
			return aExt.Index == bExt.Index && isSameOrRelated(aExt.Tuple, bExt.Tuple)
		}
	}
	aVal, aInfo := getRealValueFromOperation(a)
	bVal, bInfo := getRealValueFromOperation(b)
	if aVal == bVal && aInfo.op == bInfo.op {
		return true
	}
	if aField, ok := aVal.(*ssa.FieldAddr); ok {
		if bField, ok := bVal.(*ssa.FieldAddr); ok {
			return aField.Field == bField.Field && isSameOrRelated(aField.X, bField.X)
		}
	}
	if aUnOp, ok := aVal.(*ssa.UnOp); ok {
		if aUnOp.Op == token.MUL {
			if bUnOp, ok := bVal.(*ssa.UnOp); ok && bUnOp.Op == token.MUL {
				return isSameOrRelated(aUnOp.X, bUnOp.X)
			}
		}
	}
	return false
}

func explicitValsInRange(explicitPosVals []uint, explicitNegVals []int, dstInt IntTypeInfo) bool {
	if len(explicitPosVals) == 0 && len(explicitNegVals) == 0 {
		return false
	}
	for _, val := range explicitPosVals {
		if val > dstInt.Max {
			return false
		}
	}
	for _, val := range explicitNegVals {
		if val < dstInt.Min {
			return false
		}
	}
	return true
}

// resolveRange combines definition-based range analysis (computeRange) with dominator-based constraints (If blocks) to determine the full range of a value.
func (s *overflowState) resolveRange(v ssa.Value, block *ssa.BasicBlock, visited map[ssa.Value]bool) rangeResult {
	key := rangeCacheKey{block: block, val: v}
	if res, ok := s.rangeCache[key]; ok {
		return res
	}
	isSrcUnsigned := strings.HasPrefix(v.Type().Underlying().String(), "uint")
	// Track bounds
	result := rangeResult{
		minValue: 0,
		maxValue: maxUint64,
	}
	if !isSrcUnsigned {
		result.minValue = toUint64(minInt64)
		result.maxValue = maxInt64
	}

	if isNonNegative(v) {
		result.minValue = maxBounds(result.minValue, 0, isSrcUnsigned)
		result.minValueSet = true
	}

	// Range from definition
	defRange := s.computeRange(v, block, visited)
	if defRange.isRangeCheck || defRange.minValueSet || defRange.maxValueSet {
		result.isRangeCheck = true
		if defRange.minValueSet {
			result.minValue = maxBounds(result.minValue, defRange.minValue, isSrcUnsigned)
			result.minValueSet = true
		}
		if defRange.maxValueSet {
			result.maxValue = minBounds(result.maxValue, defRange.maxValue, isSrcUnsigned)
			result.maxValueSet = true
		}
	}

	// Check all dominating If instructions.
	idoms := getDominators(block)
	for _, idom := range idoms {
		for _, instr := range idom.Instrs {
			if vIf, ok := instr.(*ssa.If); ok {
				domRes := s.getResultRangeForValue(vIf, v, block)
				if domRes.isRangeCheck {
					result.isRangeCheck = true
					if domRes.minValueSet {
						result.minValue = maxBounds(result.minValue, domRes.minValue, isSrcUnsigned)
						result.minValueSet = true
					}
					if domRes.maxValueSet {
						result.maxValue = minBounds(result.maxValue, domRes.maxValue, isSrcUnsigned)
						result.maxValueSet = true
					}
					result.explicitPositiveVals = append(result.explicitPositiveVals, domRes.explicitPositiveVals...)
					result.explicitNegativeVals = append(result.explicitNegativeVals, domRes.explicitNegativeVals...)
				}
			}
		}
	}

	// Range from operand propagation (Recursive resolution for MUL/QUO)
	// This is needed because computeRange does not see dominators of operands.
	// We only apply this if the operand has a range derived from constraints (isRangeCheck),
	// to avoid regressions in pure definition-based constant handling.
	if binOp, ok := v.(*ssa.BinOp); ok {
		switch binOp.Op {
		case token.ADD:
			// Handle x+C or C+x
			if val, ok := GetConstantInt64(binOp.Y); ok {
				subRes := s.resolveRange(binOp.X, block, visited)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.minValue)+val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.maxValue)+val), false, isSrcUnsigned)
					}
				}
			} else if val, ok := GetConstantInt64(binOp.X); ok {
				subRes := s.resolveRange(binOp.Y, block, visited)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(&result, toUint64(val+toInt64(subRes.minValue)), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(&result, toUint64(val+toInt64(subRes.maxValue)), false, isSrcUnsigned)
					}
				}
			}
		case token.SUB:
			// Handle x-C. C-x logic is harder (inverts min/max), skipping for simplicity/safety unless needed.
			if val, ok := GetConstantInt64(binOp.Y); ok {
				subRes := s.resolveRange(binOp.X, block, visited)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.minValue)-val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.maxValue)-val), false, isSrcUnsigned)
					}
				}
			}
		case token.MUL:
			val, ok := GetConstantUint64(binOp.Y)
			if !ok {
				val, ok = GetConstantUint64(binOp.X)
			}
			if ok && val != 0 {
				var subRes rangeResult
				if _, isConst := binOp.Y.(*ssa.Const); isConst {
					subRes = s.resolveRange(binOp.X, block, visited)
				} else {
					subRes = s.resolveRange(binOp.Y, block, visited)
				}

				if subRes.maxValueSet {
					hi, _ := bits.Mul64(subRes.maxValue, val)
					if hi != 0 {
						break
					}
				}

				if subRes.minValueSet && subRes.isRangeCheck {
					updateRangeMinMax(&result, subRes.minValue*val, true, isSrcUnsigned)
				}
				if subRes.maxValueSet && subRes.isRangeCheck {
					updateRangeMinMax(&result, subRes.maxValue*val, false, isSrcUnsigned)
				}
			}
		case token.SHL:
			if val, ok := GetConstantInt64(binOp.Y); ok && val >= 0 {
				subRes := s.resolveRange(binOp.X, block, visited)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						newMin := subRes.minValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
						// Check for overflow/wrap-around
						// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
						if newMin>>uint(val) == subRes.minValue {
							updateRangeMinMax(&result, newMin, true, isSrcUnsigned)
						}
					}
					if subRes.maxValueSet {
						newMax := subRes.maxValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
						// Check for overflow/wrap-around
						// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
						if newMax>>uint(val) == subRes.maxValue {
							updateRangeMinMax(&result, newMax, false, isSrcUnsigned)
						}
					}
				}
			}
		case token.SHR:
			if val, ok := GetConstantInt64(binOp.Y); ok && val >= 0 {
				subRes := s.resolveRange(binOp.X, block, visited)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(&result, subRes.minValue>>uint(val), true, isSrcUnsigned) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					}
					if subRes.maxValueSet {
						updateRangeMinMax(&result, subRes.maxValue>>uint(val), false, isSrcUnsigned) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					}
				}
			}
		case token.QUO:
			if val, ok := GetConstantInt64(binOp.Y); ok && val != 0 {
				subRes := s.resolveRange(binOp.X, block, visited)
				if val > 0 {
					if subRes.minValueSet && subRes.isRangeCheck {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.minValue)/val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet && subRes.isRangeCheck {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.maxValue)/val), false, isSrcUnsigned)
					}
				} else {
					if subRes.maxValueSet && subRes.isRangeCheck {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.maxValue)/val), true, isSrcUnsigned)
					}
					if subRes.minValueSet && subRes.isRangeCheck {
						updateRangeMinMax(&result, toUint64(toInt64(subRes.minValue)/val), false, isSrcUnsigned)
					}
				}
			}
		}
	}

	// Fallback to type bounds if not set
	if !result.minValueSet || !result.maxValueSet {
		if srcInt, err := ParseIntType(v.Type().Underlying().String()); err == nil {
			if !result.minValueSet {
				result.minValue = toUint64(int64(srcInt.Min))
				result.minValueSet = true
			}
			if !result.maxValueSet {
				result.maxValue = uint64(srcInt.Max)
				result.maxValueSet = true
			}
		}
	}
	// Persist in cache
	s.rangeCache[key] = result
	return result
}
