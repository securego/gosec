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
	"go/constant"
	"go/token"
	"go/types"
	"log"
	"math"
	"math/bits"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

// MaxDepth defines the maximum recursion depth for SSA analysis to avoid infinite loops and memory exhaustion.
const MaxDepth = 20

const (
	minInt64  = int64(math.MinInt64)
	maxUint64 = uint64(math.MaxUint64)
	maxInt64  = uint64(math.MaxInt64)
)

// SSAAnalyzerResult contains various information returned by the
// SSA analysis along with some configuration
type SSAAnalyzerResult struct {
	Config map[string]any
	Logger *log.Logger
	SSA    *buildssa.SSA
}

// IntTypeInfo represents integer type properties
type IntTypeInfo struct {
	Signed bool
	Size   int
	Min    int
	Max    uint
}

type rangeResult struct {
	minValue             uint64
	maxValue             uint64
	minValueSet          bool
	maxValueSet          bool
	explicitPositiveVals []uint
	explicitNegativeVals []int
	isRangeCheck         bool
}

type rangeCacheKey struct {
	block *ssa.BasicBlock
	val   ssa.Value
}

type RangeAnalyzer struct {
	RangeCache map[rangeCacheKey]*rangeResult
	ResultPool []*rangeResult
	Depth      int
	BlockMap   map[*ssa.BasicBlock]bool
	ValueMap   map[ssa.Value]bool
}

type operationInfo struct {
	op      string
	extra   ssa.Value
	flipped bool
}

var intTypeRegexp = regexp.MustCompile(`^(?P<type>u?int)(?P<size>\d{1,2})?$`)

// isSliceInsideBounds checks if the requested slice range is within the parent slice's boundaries.
func isSliceInsideBounds(l, h int, cl, ch int) bool {
	return (l <= cl && h >= ch) && (l <= ch && h >= cl)
}

// isThreeIndexSliceInsideBounds validates the boundaries and capacity of a 3-index slice (s[i:j:k]).
func isThreeIndexSliceInsideBounds(l, h, maxIdx int, oldCap int) bool {
	return l >= 0 && h >= l && maxIdx >= h && maxIdx <= oldCap
}

// BuildDefaultAnalyzers returns the default list of analyzers
func BuildDefaultAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		newConversionOverflowAnalyzer("G115", "Type conversion which leads to integer overflow"),
		newSliceBoundsAnalyzer("G602", "Possible slice bounds out of range"),
		newHardCodedNonce("G407", "Use of hardcoded IV/nonce for encryption"),
	}
}

// getSSAResult retrieves the SSA result from analysis pass
func getSSAResult(pass *analysis.Pass) (*SSAAnalyzerResult, error) {
	result, ok := pass.ResultOf[buildssa.Analyzer]
	if !ok {
		return nil, fmt.Errorf("no SSA result found in the analysis pass")
	}
	ssaResult, ok := result.(*SSAAnalyzerResult)
	if !ok {
		return nil, fmt.Errorf("the analysis pass result is not of type SSA")
	}
	return ssaResult, nil
}

// newIssue creates a new gosec issue
func newIssue(analyzerID string, desc string, fileSet *token.FileSet,
	pos token.Pos, severity, confidence issue.Score,
) *issue.Issue {
	file := fileSet.File(pos)
	// This can occur when there is a compilation issue into the code.
	if file == nil {
		return &issue.Issue{}
	}
	line := file.Line(pos)
	col := file.Position(pos).Column

	return &issue.Issue{
		RuleID:     analyzerID,
		File:       file.Name(),
		Line:       strconv.Itoa(line),
		Col:        strconv.Itoa(col),
		Severity:   severity,
		Confidence: confidence,
		What:       desc,
		Cwe:        issue.GetCweByRule(analyzerID),
		Code:       issueCodeSnippet(fileSet, pos),
	}
}

func issueCodeSnippet(fileSet *token.FileSet, pos token.Pos) string {
	file := fileSet.File(pos)

	start := (int64)(file.Line(pos))
	if start-issue.SnippetOffset > 0 {
		start = start - issue.SnippetOffset
	}
	end := (int64)(file.Line(pos))
	end = end + issue.SnippetOffset

	var code string
	if file, err := os.Open(file.Name()); err == nil {
		defer file.Close() // #nosec
		code, err = issue.CodeSnippet(file, start, end)
		if err != nil {
			return err.Error()
		}
	}
	return code
}

// ParseIntType parses an integer type string into IntTypeInfo
func ParseIntType(intType string) (IntTypeInfo, error) {
	matches := intTypeRegexp.FindStringSubmatch(intType)
	if matches == nil {
		return IntTypeInfo{}, fmt.Errorf("no integer type match found for %s", intType)
	}

	it := matches[intTypeRegexp.SubexpIndex("type")]
	is := matches[intTypeRegexp.SubexpIndex("size")]

	signed := it == "int"
	intSize := strconv.IntSize
	if is != "" {
		var err error
		intSize, err = strconv.Atoi(is)
		if err != nil {
			return IntTypeInfo{}, fmt.Errorf("failed to parse the integer type size: %w", err)
		}
	}

	if intSize != 8 && intSize != 16 && intSize != 32 && intSize != 64 && is != "" {
		return IntTypeInfo{}, fmt.Errorf("invalid bit size: %d", intSize)
	}

	var minVal int
	var maxVal uint

	if signed {
		switch intSize {
		case 8:
			minVal = math.MinInt8
			maxVal = math.MaxInt8
		case 16:
			minVal = math.MinInt16
			maxVal = math.MaxInt16
		case 32:
			minVal = math.MinInt32
			maxVal = math.MaxInt32
		case 64:
			minVal = math.MinInt64
			// We are on 64-bit architecture where uint is 64-bit
			maxVal = uint(math.MaxInt64)
		default:
			return IntTypeInfo{}, fmt.Errorf("unsupported bit size: %d", intSize)
		}
	} else {
		minVal = 0
		switch intSize {
		case 8:
			maxVal = math.MaxUint8
		case 16:
			maxVal = math.MaxUint16
		case 32:
			maxVal = math.MaxUint32
		case 64:
			// We are on 64-bit architecture where uint is 64-bit
			maxVal = uint(math.MaxUint64)
		default:
			return IntTypeInfo{}, fmt.Errorf("unsupported bit size: %d", intSize)
		}
	}

	return IntTypeInfo{
		Signed: signed,
		Size:   intSize,
		Min:    minVal,
		Max:    maxVal,
	}, nil
}

// GetConstantInt64 extracts a constant int64 value from an ssa.Value
func GetConstantInt64(v ssa.Value) (int64, bool) {
	if c, ok := v.(*ssa.Const); ok {
		if c.Value != nil {
			if val, ok := constant.Int64Val(c.Value); ok {
				return val, true
			}
		}
	}
	if unOp, ok := v.(*ssa.UnOp); ok && unOp.Op == token.SUB {
		if val, ok := GetConstantInt64(unOp.X); ok {
			return -val, true
		}
	}
	return 0, false
}

// GetConstantUint64 extracts a constant uint64 value from an ssa.Value
func GetConstantUint64(v ssa.Value) (uint64, bool) {
	if c, ok := v.(*ssa.Const); ok {
		if c.Value != nil {
			if val, ok := constant.Uint64Val(c.Value); ok {
				return val, true
			}
		}
	}
	return 0, false
}

// GetSliceBounds extracts low, high, and max indices from a slice instruction
func GetSliceBounds(s *ssa.Slice) (int, int, int) {
	var low, high, maxIdx int
	if s.Low != nil {
		if val, ok := GetConstantInt64(s.Low); ok {
			low = int(val)
		}
	}
	if s.High != nil {
		if val, ok := GetConstantInt64(s.High); ok {
			high = int(val)
		}
	}
	if s.Max != nil {
		if val, ok := GetConstantInt64(s.Max); ok {
			maxIdx = int(val)
		}
	}
	return low, high, maxIdx
}

// GetSliceRange extracts low and high indices as int64.
// High is returned as -1 if it's missing (extends to the end).
func GetSliceRange(s *ssa.Slice) (int64, int64) {
	var low, high int64 = 0, -1
	if s.Low != nil {
		if val, ok := GetConstantInt64(s.Low); ok {
			low = val
		}
	}
	if s.High != nil {
		if val, ok := GetConstantInt64(s.High); ok {
			high = val
		}
	}
	return low, high
}

// ComputeSliceNewCap determines the new capacity of a slice based on the slicing operation.
// l, h, maxIdx are the extracted low, high, and max indices. oldCap is the capacity of the original slice.
// It handles both 2-index ([:]) and 3-index ([: :]) slice expressions.
func ComputeSliceNewCap(l, h, maxIdx, oldCap int) int {
	if maxIdx > 0 {
		return maxIdx - l
	}
	if l == 0 && h == 0 {
		return oldCap
	}
	if l > 0 && h == 0 {
		return oldCap - l
	}
	if l == 0 && h > 0 {
		return h
	}
	return h - l
}

// IsFullSlice checks if the slice operation covers the entire buffer.
func IsFullSlice(sl *ssa.Slice, bufferLen int64) bool {
	l, h := GetSliceRange(sl)
	if l != 0 {
		return false
	}
	if h < 0 {
		return true
	}
	return bufferLen >= 0 && h == bufferLen
}

// IsSubSlice checks if the 'sub' slice is contained within the 'super' slice.
func IsSubSlice(sub, super *ssa.Slice) bool {
	l1, h1 := GetSliceRange(sub)   // child
	l2, h2 := GetSliceRange(super) // parent
	if l2 > l1 {
		return false
	}
	if h2 < 0 {
		return true // parent covers all, so child is sub
	}
	if h1 < 0 {
		return false // parent has bound but child doesn't
	}
	return h1 <= h2
}

// GetBufferLen attempts to find the constant length of a buffer/slice/array
func GetBufferLen(val ssa.Value) int64 {
	current := val
	for {
		t := current.Type()
		if ptr, ok := t.Underlying().(*types.Pointer); ok {
			t = ptr.Elem().Underlying()
		}
		if arr, ok := t.(*types.Array); ok {
			return arr.Len()
		}
		if sl, ok := current.(*ssa.Slice); ok {
			current = sl.X
			continue
		}
		break
	}
	return -1
}

// BuildCallerMap builds a map of function names to their call sites
func BuildCallerMap(funcs []*ssa.Function) map[string][]*ssa.Call {
	callerMap := make(map[string][]*ssa.Call)
	for _, f := range funcs {
		for _, b := range f.Blocks {
			for _, i := range b.Instrs {
				if c, ok := i.(*ssa.Call); ok {
					var name string
					if c.Call.Method != nil {
						name = c.Call.Method.FullName()
					} else {
						name = c.Call.Value.String()
					}
					callerMap[name] = append(callerMap[name], c)
				}
			}
		}
	}
	return callerMap
}

// toUint64 casts int64 to uint64 preserving the bit pattern (2's complement) and suppresses the linter warning.
func toUint64(i int64) uint64 {
	return uint64(i) // #nosec
}

// toInt64 casts uint64 to int64 preserving the bit pattern and suppresses the linter warning.
func toInt64(u uint64) int64 {
	return int64(u) // #nosec
}

// GetDominators returns a list of dominator blocks for the given block, in order from root to the block.
func GetDominators(block *ssa.BasicBlock) []*ssa.BasicBlock {
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

// Precedes returns true if instruction a is executed before instruction b.
// It assumes both instructions belong to the same function.
func (ra *RangeAnalyzer) Precedes(a, b ssa.Instruction) bool {
	if a == b {
		return true
	}
	if a.Block() != b.Block() {
		return ra.IsReachable(a.Block(), b.Block())
	}
	// Same block: check order in Instrs
	for _, instr := range a.Block().Instrs {
		if instr == a {
			return true
		}
		if instr == b {
			return false
		}
	}
	return false
}

func (res *rangeResult) Reset() {
	res.minValue = toUint64(minInt64)
	res.maxValue = maxUint64
	res.minValueSet = false
	res.maxValueSet = false
	res.explicitPositiveVals = res.explicitPositiveVals[:0]
	res.explicitNegativeVals = res.explicitNegativeVals[:0]
	res.isRangeCheck = false
}

func (res *rangeResult) CopyFrom(other *rangeResult) {
	res.minValue = other.minValue
	res.maxValue = other.maxValue
	res.minValueSet = other.minValueSet
	res.maxValueSet = other.maxValueSet
	res.explicitPositiveVals = append(res.explicitPositiveVals[:0], other.explicitPositiveVals...)
	res.explicitNegativeVals = append(res.explicitNegativeVals[:0], other.explicitNegativeVals...)
	res.isRangeCheck = other.isRangeCheck
}

func NewRangeAnalyzer() *RangeAnalyzer {
	return &RangeAnalyzer{
		RangeCache: make(map[rangeCacheKey]*rangeResult),
		ResultPool: make([]*rangeResult, 0, 32),
		BlockMap:   make(map[*ssa.BasicBlock]bool),
		ValueMap:   make(map[ssa.Value]bool),
	}
}

func (ra *RangeAnalyzer) ResetCache() {
	for _, res := range ra.RangeCache {
		ra.releaseResult(res)
	}
	clear(ra.RangeCache)
}

func (ra *RangeAnalyzer) acquireResult() *rangeResult {
	if len(ra.ResultPool) > 0 {
		idx := len(ra.ResultPool) - 1
		res := ra.ResultPool[idx]
		ra.ResultPool = ra.ResultPool[:idx]
		res.Reset()
		return res
	}
	res := &rangeResult{}
	res.Reset()
	return res
}

func (ra *RangeAnalyzer) releaseResult(res *rangeResult) {
	if res != nil {
		ra.ResultPool = append(ra.ResultPool, res)
	}
}

// resolveRange combines definition-based range analysis (computeRange) with dominator-based constraints (If blocks) to determine the full range of a value.
func (ra *RangeAnalyzer) ResolveRange(v ssa.Value, block *ssa.BasicBlock) *rangeResult {
	key := rangeCacheKey{block: block, val: v}
	if res, ok := ra.RangeCache[key]; ok {
		ret := ra.acquireResult()
		ret.CopyFrom(res)
		return ret
	}

	isSrcUnsigned := isUint(v)
	result := ra.acquireResult()
	// result is initialized to wide range (MinInt64, MaxUint64) by acquireResult/Reset
	if isSrcUnsigned {
		result.minValue = 0
	} else {
		result.maxValue = maxInt64
	}

	// Check for explicit range checks.
	if vIndex, ok := v.(*ssa.IndexAddr); ok {
		res := ra.ResolveRange(vIndex.Index, vIndex.Block())
		if res.isRangeCheck && res.minValueSet && res.maxValueSet {
			// If the index itself has a known range, apply it.
			result.minValue = maxBounds(result.minValue, res.minValue, isSrcUnsigned)
			result.maxValue = minBounds(result.maxValue, res.maxValue, isSrcUnsigned)
			result.minValueSet = true
			result.maxValueSet = true
			result.isRangeCheck = true
		}
		ra.releaseResult(res)
	}

	if ra.Depth > MaxDepth {
		ra.RangeCache[key] = result
		return result
	}

	ra.Depth++
	defer func() { ra.Depth-- }()

	// First, check basic properties
	isSrcUnsigned = isUint(v)
	isNonNeg := ra.IsNonNegative(v)
	if isNonNeg {
		result.minValue = 0
		result.minValueSet = true
		result.isRangeCheck = true
	} else if isSrcUnsigned {
		result.minValue = 0
	} else {
		result.maxValue = maxInt64
	}

	// Range from definition
	defRange := ra.ComputeRange(v, block)
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
	// ComputeRange returns a temporary result, release it
	ra.releaseResult(defRange)

	// Range from control flow constraints
	doms := GetDominators(block)
	for _, dom := range doms {
		if vIf, ok := dom.Instrs[len(dom.Instrs)-1].(*ssa.If); ok {
			var finalResIf *rangeResult
			matchCount := 0
			for i, succ := range dom.Succs {
				reach := ra.IsReachable(succ, block)
				if reach {
					matchCount++
					if resIf := ra.getResultRangeForIfEdge(vIf, i == 0, v); resIf != nil {
						if matchCount == 1 {
							finalResIf = resIf
						} else {
							ra.releaseResult(resIf)
							if finalResIf != nil {
								ra.releaseResult(finalResIf)
								finalResIf = nil
							}
						}
					}
				}
			}
			if matchCount == 1 && finalResIf != nil {
				if finalResIf.minValueSet {
					result.minValue = maxBounds(result.minValue, finalResIf.minValue, isSrcUnsigned)
					result.minValueSet = true
				}
				if finalResIf.maxValueSet {
					result.maxValue = minBounds(result.maxValue, finalResIf.maxValue, isSrcUnsigned)
					result.maxValueSet = true
				}
				if finalResIf.isRangeCheck {
					result.isRangeCheck = true
				}
				ra.releaseResult(finalResIf)
			}
		}
	}

	// Persist in cache
	cached := ra.acquireResult()
	cached.CopyFrom(result)
	ra.RangeCache[key] = cached
	return result
}

// IsReachable returns true if there is a path from the start block to the target block in the CFG.
// It uses the RangeAnalyzer's BlockMap to cache visited blocks and avoid allocations.
func (ra *RangeAnalyzer) IsReachable(start, target *ssa.BasicBlock) bool {
	if start == target {
		return true
	}
	clear(ra.BlockMap)
	var reach func(*ssa.BasicBlock) bool
	reach = func(curr *ssa.BasicBlock) bool {
		if curr == target {
			return true
		}
		if ra.BlockMap[curr] {
			return false
		}
		ra.BlockMap[curr] = true
		return slices.ContainsFunc(curr.Succs, reach)
	}
	return reach(start)
}

func (ra *RangeAnalyzer) getResultRangeForIfEdge(vIf *ssa.If, isTrue bool, v ssa.Value) *rangeResult {
	res := ra.acquireResult()
	binOp, _ := vIf.Cond.(*ssa.BinOp)
	if binOp != nil && IsRangeCheck(vIf.Cond, v) {
		ra.updateResultFromBinOpForValue(res, binOp, v, isTrue)
	}

	return res
}

func (ra *RangeAnalyzer) updateResultFromBinOpForValue(result *rangeResult, binOp *ssa.BinOp, v ssa.Value, successPathConvert bool) {
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
			isSrcUnsigned := isUint(v)
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
							if val < minInt64/vMul {
								return
							}
							val = val * vMul
						}
					} else {
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
}

// IsRangeCheck determines if an instruction is part of a range check for a value.
func IsRangeCheck(v ssa.Value, x ssa.Value) bool {
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
	result.isRangeCheck = true
}

func updateMinMaxForLessOrEqual(result *rangeResult, val int64, op token.Token, operandsFlipped bool, successPathConvert bool) {
	if successPathConvert != operandsFlipped {
		result.maxValue = toUint64(val)
		if op == token.LSS {
			result.maxValue--
		}
		result.maxValueSet = true
		result.isRangeCheck = true
	} else {
		// Path where x >= val
		result.minValue = toUint64(val)
		if op == token.LEQ {
			result.minValue++ // !(x <= val) -> x > val
		}
		result.minValueSet = true
		result.isRangeCheck = true
	}
}

func updateMinMaxForGreaterOrEqual(result *rangeResult, val int64, op token.Token, operandsFlipped bool, successPathConvert bool) {
	if successPathConvert != operandsFlipped {
		result.minValue = toUint64(val)
		if op == token.GTR {
			result.minValue++
		}
		result.minValueSet = true
		result.isRangeCheck = true
	} else {
		// Path where x < val
		result.maxValue = toUint64(val)
		if op == token.GEQ {
			result.maxValue-- // !(x >= val) -> x < val
		}
		result.maxValueSet = true
		result.isRangeCheck = true
	}
}

func (ra *RangeAnalyzer) IsNonNegative(v ssa.Value) bool {
	clear(ra.ValueMap)
	return ra.isNonNegativeRecursive(v)
}

func (ra *RangeAnalyzer) isNonNegativeRecursive(v ssa.Value) bool {
	if ra.ValueMap[v] {
		return true // Assume non-negative to break cycles
	}
	ra.ValueMap[v] = true

	if isUint(v) {
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
					if !ra.isNonNegativeRecursive(arg) {
						return false
					}
				}
				return len(v.Call.Args) > 0
			case "max":
				for _, arg := range v.Call.Args {
					if ra.isNonNegativeRecursive(arg) {
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
			return ra.isNonNegativeRecursive(v.X) && ra.isNonNegativeRecursive(v.Y)
		case token.REM, token.AND, token.SHR:
			return ra.isNonNegativeRecursive(v.X)
		}
	case *ssa.Const:
		if val, ok := GetConstantInt64(v); ok && val >= 0 {
			return true
		}
	case *ssa.Phi:
		allNonNeg := true
		for _, edge := range v.Edges {
			if !ra.isNonNegativeRecursive(edge) {
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
		if isUint(v.X) {
			return true
		}
	}
	return false
}

func (ra *RangeAnalyzer) ComputeRange(v ssa.Value, block *ssa.BasicBlock) *rangeResult {
	res := ra.acquireResult()
	isSrcUnsigned := isUint(v)

	switch v := v.(type) {
	case *ssa.BinOp:
		switch v.Op {
		case token.ADD:
			if val, ok := GetConstantInt64(v.Y); ok {
				subRes := ra.ResolveRange(v.X, block)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subRes.minValue)+val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subRes.maxValue)+val), false, isSrcUnsigned)
					}
				}
				ra.releaseResult(subRes)
			} else if val, ok := GetConstantInt64(v.X); ok {
				subRes := ra.ResolveRange(v.Y, block)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(res, toUint64(val+toInt64(subRes.minValue)), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(res, toUint64(val+toInt64(subRes.maxValue)), false, isSrcUnsigned)
					}
				}
				ra.releaseResult(subRes)
			} else {
				subResX := ra.ResolveRange(v.X, block)
				subResY := ra.ResolveRange(v.Y, block)
				if subResX.isRangeCheck || subResY.isRangeCheck {
					if subResX.minValueSet && subResY.minValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subResX.minValue)+toInt64(subResY.minValue)), true, isSrcUnsigned)
					}
					if subResX.maxValueSet && subResY.maxValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subResX.maxValue)+toInt64(subResY.maxValue)), false, isSrcUnsigned)
					}
					if res.minValueSet || res.maxValueSet {
						res.isRangeCheck = true
					}
				}
				ra.releaseResult(subResX)
				ra.releaseResult(subResY)
			}
		case token.SUB:
			if val, ok := GetConstantInt64(v.Y); ok {
				subRes := ra.ResolveRange(v.X, block)
				if subRes.isRangeCheck {
					if subRes.minValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subRes.minValue)-val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet {
						updateRangeMinMax(res, toUint64(toInt64(subRes.maxValue)-val), false, isSrcUnsigned)
					}
				}
				ra.releaseResult(subRes)
			} else if val, ok := GetConstantInt64(v.X); ok {
				subRes := ra.ResolveRange(v.Y, block)
				if subRes.isRangeCheck {
					if subRes.maxValueSet {
						// res = val - subRes.maxValue (this is the new min if subtract max)
						updateRangeMinMax(res, toUint64(val-toInt64(subRes.maxValue)), true, isSrcUnsigned)
					}
					if subRes.minValueSet {
						// res = val - subRes.minValue (this is the new max if subtract min)
						updateRangeMinMax(res, toUint64(val-toInt64(subRes.minValue)), false, isSrcUnsigned)
					}
				}
				ra.releaseResult(subRes)
			} else {
				subResX := ra.ResolveRange(v.X, block)
				subResY := ra.ResolveRange(v.Y, block)
				if subResX.isRangeCheck || subResY.isRangeCheck {
					if subResX.minValueSet && subResY.maxValueSet {
						// Min = MinX - MaxY
						updateRangeMinMax(res, toUint64(toInt64(subResX.minValue)-toInt64(subResY.maxValue)), true, isSrcUnsigned)
					}
					if subResX.maxValueSet && subResY.minValueSet {
						// Max = MaxX - MinY
						updateRangeMinMax(res, toUint64(toInt64(subResX.maxValue)-toInt64(subResY.minValue)), false, isSrcUnsigned)
					}
					if res.minValueSet || res.maxValueSet {
						res.isRangeCheck = true
					}
				}
				ra.releaseResult(subResX)
				ra.releaseResult(subResY)
			}
		case token.MUL:
			val, ok := GetConstantUint64(v.Y)
			if !ok {
				val, ok = GetConstantUint64(v.X)
			}
			if ok && val != 0 {
				var subRes *rangeResult
				if _, isConst := v.Y.(*ssa.Const); isConst {
					subRes = ra.ResolveRange(v.X, block)
				} else {
					subRes = ra.ResolveRange(v.Y, block)
				}

				if subRes.maxValueSet {
					hi, _ := bits.Mul64(subRes.maxValue, val)
					if hi == 0 {
						if subRes.minValueSet && subRes.isRangeCheck {
							updateRangeMinMax(res, subRes.minValue*val, true, isSrcUnsigned)
						}
						if subRes.maxValueSet && subRes.isRangeCheck {
							updateRangeMinMax(res, subRes.maxValue*val, false, isSrcUnsigned)
						}
					}
				}
			}
		case token.SHL:
			if val, ok := GetConstantInt64(v.Y); ok && val >= 0 {
				subRes := ra.ResolveRange(v.X, block)
				if subRes.minValueSet {
					newMin := subRes.minValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					if newMin>>uint(val) == subRes.minValue {
						updateRangeMinMax(res, newMin, true, isSrcUnsigned)
					}
				}
				if subRes.maxValueSet {
					newMax := subRes.maxValue << uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					// #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					if newMax>>uint(val) == subRes.maxValue {
						updateRangeMinMax(res, newMax, false, isSrcUnsigned)
					}
				}
			}
		case token.SHR:
			if val, ok := GetConstantInt64(v.Y); ok && val >= 0 {
				subRes := ra.ResolveRange(v.X, block)
				if subRes.minValueSet {
					updateRangeMinMax(res, subRes.minValue>>uint(val), true, isSrcUnsigned) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
				}
				if subRes.maxValueSet {
					updateRangeMinMax(res, subRes.maxValue>>uint(val), false, isSrcUnsigned) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
				} else {
					// Even if we don't have a max value set, we know the upper bound from the type.
					srcInt, _ := ParseIntType(v.X.Type().Underlying().String())
					res.maxValue = uint64(srcInt.Max) >> uint(val) // #nosec G115 - WORKAROUND for old golangci-lint, remove when updated
					res.maxValueSet = true
					res.isRangeCheck = true
				}
			}
		case token.QUO:
			if val, ok := GetConstantInt64(v.Y); ok && val != 0 {
				subRes := ra.ResolveRange(v.X, block)
				if val > 0 {
					if subRes.minValueSet && subRes.isRangeCheck {
						updateRangeMinMax(res, toUint64(toInt64(subRes.minValue)/val), true, isSrcUnsigned)
					}
					if subRes.maxValueSet && subRes.isRangeCheck {
						updateRangeMinMax(res, toUint64(toInt64(subRes.maxValue)/val), false, isSrcUnsigned)
					}
				} else {
					if subRes.maxValueSet && subRes.isRangeCheck {
						updateRangeMinMax(res, toUint64(toInt64(subRes.maxValue)/val), true, isSrcUnsigned)
					}
					if subRes.minValueSet && subRes.isRangeCheck {
						updateRangeMinMax(res, toUint64(toInt64(subRes.minValue)/val), false, isSrcUnsigned)
					}
				}
			}
		case token.REM:
			if val, ok := GetConstantInt64(v.Y); ok && val > 0 {
				res.minValue = toUint64(-(val - 1))
				res.maxValue = toUint64(val - 1)
				res.minValueSet = true
				res.maxValueSet = true
				res.isRangeCheck = true
				// If we know x >= 0, we can refine to [0, val-1]
				subRes := ra.ResolveRange(v.X, block)
				if (subRes.minValueSet && toInt64(subRes.minValue) >= 0) || ra.IsNonNegative(v.X) {
					res.minValue = 0
				}
				ra.releaseResult(subRes)
			}
		case token.AND:
			if val, ok := GetConstantInt64(v.Y); ok && val >= 0 {
				res.minValue = 0
				res.maxValue = uint64(val)
				res.minValueSet = true
				res.maxValueSet = true
				res.isRangeCheck = true
			} else if val, ok := GetConstantInt64(v.X); ok && val >= 0 {
				res.minValue = 0
				res.maxValue = uint64(val)
				res.minValueSet = true
				res.maxValueSet = true
				res.isRangeCheck = true
			}
		}
	case *ssa.Call:
		if fn, ok := v.Call.Value.(*ssa.Builtin); ok {
			switch fn.Name() {
			case "min":
				if len(v.Call.Args) > 0 {
					for i, arg := range v.Call.Args {
						argRes := ra.ResolveRange(arg, block)
						if i == 0 {
							res.CopyFrom(argRes)
						} else {
							if res.minValueSet && argRes.minValueSet {
								res.minValue = minBounds(res.minValue, argRes.minValue, isSrcUnsigned)
							} else {
								res.minValueSet = false
							}
							if res.maxValueSet && argRes.maxValueSet {
								res.maxValue = minBounds(res.maxValue, argRes.maxValue, isSrcUnsigned)
							} else if argRes.maxValueSet {
								res.maxValue = argRes.maxValue
								res.maxValueSet = true
							}
						}
						ra.releaseResult(argRes)
					}
					res.isRangeCheck = true
				}
			case "max":
				if len(v.Call.Args) > 0 {
					for i, arg := range v.Call.Args {
						argRes := ra.ResolveRange(arg, block)
						if i == 0 {
							res.CopyFrom(argRes)
						} else {
							if res.minValueSet && argRes.minValueSet {
								res.minValue = maxBounds(res.minValue, argRes.minValue, isSrcUnsigned)
							} else if argRes.minValueSet {
								res.minValue = argRes.minValue
								res.minValueSet = true
							}
							if res.maxValueSet && argRes.maxValueSet {
								res.maxValue = maxBounds(res.maxValue, argRes.maxValue, isSrcUnsigned)
							} else {
								res.maxValueSet = false
							}
						}
						ra.releaseResult(argRes)
					}
					res.isRangeCheck = true
				}
			}
		}
	case *ssa.Phi:
		for _, edge := range v.Edges {
			subRes := ra.ResolveRange(edge, block)
			if subRes.minValueSet {
				updateRangeMinMax(res, subRes.minValue, true, isSrcUnsigned)
			}
			if subRes.maxValueSet {
				updateRangeMinMax(res, subRes.maxValue, false, isSrcUnsigned)
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
	case *ssa.Const:
		if val, ok := GetConstantInt64(v); ok {
			res.minValue = toUint64(val)
			res.maxValue = toUint64(val)
			res.minValueSet = true
			res.maxValueSet = true
			res.isRangeCheck = true
		}
	}

	return res
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

// isUint checks if the value's type is an unsigned integer.
func isUint(v ssa.Value) bool {
	return strings.HasPrefix(v.Type().Underlying().String(), "uint")
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

// getRealValueFromOperation decomposes an SSA value into its base value and any simple arithmetic operation applied to it.
func getRealValueFromOperation(v ssa.Value) (ssa.Value, operationInfo) {
	switch v := v.(type) {
	case *ssa.BinOp:
		switch v.Op {
		case token.SHL, token.ADD, token.SUB, token.SHR, token.MUL, token.QUO:
			if _, ok := GetConstantInt64(v.Y); ok {
				return v.X, operationInfo{op: v.Op.String(), extra: v.Y}
			}
			if _, ok := GetConstantInt64(v.X); ok {
				return v.Y, operationInfo{op: v.Op.String(), extra: v.X, flipped: true}
			}
		}
	case *ssa.UnOp:
		switch v.Op {
		case token.SUB:
			return v.X, operationInfo{op: "neg"}
		case token.MUL:
			// Follow pointer dereference.
			if unOp, ok := v.X.(*ssa.UnOp); ok && unOp.Op == token.MUL {
				return getRealValueFromOperation(unOp)
			}
			// If it's a field address, keep going.
			if fieldAddr, ok := v.X.(*ssa.FieldAddr); ok {
				return fieldAddr, operationInfo{op: "field"}
			}
		}
	case *ssa.FieldAddr:
		return v, operationInfo{op: "field"}
	case *ssa.Alloc:
		return v, operationInfo{op: "alloc"}
	}
	return v, operationInfo{}
}

// isEquivalent checks if two SSA values are structurally equivalent.
func isEquivalent(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Handle distinct constant pointers
	if aConst, ok := a.(*ssa.Const); ok {
		if bConst, ok := b.(*ssa.Const); ok {
			return aConst.Value == bConst.Value && aConst.Type() == bConst.Type()
		}
	}

	switch va := a.(type) {
	case *ssa.BinOp:
		if vb, ok := b.(*ssa.BinOp); ok {
			return va.Op == vb.Op && isEquivalent(va.X, vb.X) && isEquivalent(va.Y, vb.Y)
		}
	case *ssa.UnOp:
		if vb, ok := b.(*ssa.UnOp); ok {
			return va.Op == vb.Op && isEquivalent(va.X, vb.X)
		}
	}
	return false
}

// isSameOrRelated checks if two SSA values represent the same underlying variable or related struct fields.
func isSameOrRelated(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
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

// ExplicitValsInRange checks if any of the explicit positive or negative values are within the range of the destination type.
func ExplicitValsInRange(pos []uint, neg []int, dstInt IntTypeInfo) bool {
	for _, v := range pos {
		if uint64(v) <= uint64(dstInt.Max) {
			return true
		}
	}
	for _, v := range neg {
		if int64(v) >= int64(dstInt.Min) {
			return true
		}
	}
	return false
}
