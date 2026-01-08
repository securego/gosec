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
	"errors"
	"fmt"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

type bound int

const (
	lowerUnbounded bound = iota
	upperUnbounded
	unbounded
	upperBounded
	bounded
)

const maxDepth = 20

func newSliceBoundsAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runSliceBounds,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, err
	}

	issues := map[ssa.Instruction]*issue.Issue{}
	ifs := map[ssa.If]*ssa.BinOp{}
	for _, mcall := range ssaResult.SSA.SrcFuncs {
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				switch instr := instr.(type) {
				case *ssa.Alloc:
					sliceCap, err := extractSliceCapFromAlloc(instr.String())
					if err != nil {
						break
					}
					allocRefs := instr.Referrers()
					if allocRefs == nil {
						break
					}
					for _, instr := range *allocRefs {
						if slice, ok := instr.(*ssa.Slice); ok {
							if _, ok := slice.X.(*ssa.Alloc); ok {
								if slice.Parent() != nil {
									l, h, maxIdx := extractSliceBounds(slice)
									violations := []ssa.Instruction{}
									if maxIdx > 0 {
										if !isThreeIndexSliceInsideBounds(l, h, maxIdx, sliceCap) {
											violations = append(violations, slice)
										}
									} else {
										if !isSliceInsideBounds(0, sliceCap, l, h) {
											violations = append(violations, slice)
										}
									}
									newCap := computeSliceNewCap(l, h, maxIdx, sliceCap)
									trackSliceBounds(0, newCap, slice, &violations, ifs)
									for _, s := range violations {
										switch s := s.(type) {
										case *ssa.Slice:
											issues[s] = newIssue(
												pass.Analyzer.Name,
												"slice bounds out of range",
												pass.Fset,
												s.Pos(),
												issue.Low,
												issue.High)
										case *ssa.IndexAddr:
											issues[s] = newIssue(
												pass.Analyzer.Name,
												"slice index out of range",
												pass.Fset,
												s.Pos(),
												issue.Low,
												issue.High)
										}
									}
								}
							}
						}
					}
				case *ssa.IndexAddr:
					switch indexInstr := instr.X.(type) {
					case *ssa.Const:
						if indexInstr.Type().String()[:2] == "[]" {
							if indexInstr.Value == nil {
								issues[instr] = newIssue(
									pass.Analyzer.Name,
									"slice index out of range",
									pass.Fset,
									instr.Pos(),
									issue.Low,
									issue.High)

								break
							}
						}
					case *ssa.Alloc:
						if instr.Pos() > 0 {
							typeStr := indexInstr.Type().String()
							arrayLen, err := extractArrayAllocValue(typeStr) // preallocated array
							if err != nil {
								break
							}

							_, err = extractIntValueIndexAddr(instr, arrayLen)
							if err != nil {
								break
							}
							issues[instr] = newIssue(
								pass.Analyzer.Name,
								"slice index out of range",
								pass.Fset,
								instr.Pos(),
								issue.Low,
								issue.High)
						}
					}
				}
			}
		}
	}

	for ifref, binop := range ifs {
		bound, value, err := extractBinOpBound(binop)

		// New logic: attempt to handle dynamic bounds (e.g. i < len - 1)
		var loopVar ssa.Value
		var lenOffset int
		var isLenBound bool

		if err != nil {
			// If constant extraction failed, try extracting length-based bound
			if v, off, ok := extractLenBound(binop); ok {
				loopVar = v
				lenOffset = off
				isLenBound = true
				bound = upperBounded // Assume i < len... is an upper bound check
			} else {
				continue
			}
		}

		for i, block := range ifref.Block().Succs {
			if i == 1 {
				bound = invBound(bound)
			}
			var processBlock func(block *ssa.BasicBlock, depth int)
			processBlock = func(block *ssa.BasicBlock, depth int) {
				if depth == maxDepth {
					return
				}
				depth++
				for _, instr := range block.Instrs {
					if _, ok := issues[instr]; ok {
						switch bound {
						case lowerUnbounded:
							break
						case upperUnbounded, unbounded:
							delete(issues, instr)
						case upperBounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								_, _, m := extractSliceBounds(tinstr)
								if !isLenBound && isSliceInsideBounds(0, value, m, value) {
									delete(issues, instr)
								}
							case *ssa.IndexAddr:
								if isLenBound {
									if idxOffset, ok := extractIndexOffset(tinstr.Index, loopVar); ok {
										if lenOffset+idxOffset-1 < 0 {
											delete(issues, instr)
										}
									}
								} else {
									indexValue, err := extractIntValue(tinstr.Index.String())
									if err != nil {
										break
									}
									if isSliceIndexInsideBounds(value, indexValue) {
										delete(issues, instr)
									}
								}
							}
						case bounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								_, _, m := extractSliceBounds(tinstr)
								if isSliceInsideBounds(value, value, m, value) {
									delete(issues, instr)
								}
							case *ssa.IndexAddr:
								indexValue, err := extractIntValue(tinstr.Index.String())
								if err != nil {
									break
								}
								if indexValue == value {
									delete(issues, instr)
								}
							}
						}
					} else if nestedIfInstr, ok := instr.(*ssa.If); ok {
						for _, nestedBlock := range nestedIfInstr.Block().Succs {
							processBlock(nestedBlock, depth)
						}
					}
				}
			}

			processBlock(block, 0)
		}
	}

	foundIssues := []*issue.Issue{}
	for _, v := range issues {
		foundIssues = append(foundIssues, v)
	}
	if len(foundIssues) > 0 {
		return foundIssues, nil
	}
	return nil, nil
}

// extractLenBound checks if the binop is of form "Var < Len + Offset" or equivalent patterns
// (including offsets on the left-hand side like "(Var + Const) < Len")
func extractLenBound(binop *ssa.BinOp) (ssa.Value, int, bool) {
	// Only handle Less Than for now
	if binop.Op != token.LSS {
		return nil, 0, false
	}

	var loopVar ssa.Value
	var lenOffset int

	// First, try to interpret RHS as the length expression (len +/- const) and LHS as plain loop var
	loopVar = binop.X // candidate loop variable

	if _, isConst := binop.Y.(*ssa.Const); isConst {
		// RHS is a constant → cannot be a length-bound check
		return nil, 0, false
	}

	// Try to pull an offset from RHS if it is len +/- const
	if rhsBinOp, ok := binop.Y.(*ssa.BinOp); ok && (rhsBinOp.Op == token.ADD || rhsBinOp.Op == token.SUB) {
		var constVal int
		var foundConst bool

		// Check both sides for the constant (symmetric for ADD, careful for SUB)
		if c, ok := rhsBinOp.Y.(*ssa.Const); ok {
			if v, err := strconv.Atoi(c.Value.String()); err == nil {
				constVal = v
				foundConst = true
			}
		} else if c, ok := rhsBinOp.X.(*ssa.Const); ok {
			if v, err := strconv.Atoi(c.Value.String()); err == nil {
				constVal = v
				foundConst = true
			}
		}

		if foundConst {
			switch rhsBinOp.Op {
			case token.ADD:
				// len + k or k + len → same meaning
				lenOffset = constVal
			case token.SUB:
				if _, isConstOnLeft := rhsBinOp.X.(*ssa.Const); isConstOnLeft {
					// k - len → unusual for a strict upper bound, skip this pattern
					foundConst = false
				} else {
					// len - k
					lenOffset = -constVal
				}
			}
			if foundConst {
				return loopVar, lenOffset, true
			}
		}
	}

	// If we get here, RHS is a plain length (no extractable offset) or extraction failed.
	// Now try the alternative pattern: LHS is (loopVar +/- const), RHS is plain len
	if lhsBinOp, ok := binop.X.(*ssa.BinOp); ok && (lhsBinOp.Op == token.ADD || lhsBinOp.Op == token.SUB) {
		var constVal int
		var varVal ssa.Value
		var found bool

		if c, ok := lhsBinOp.Y.(*ssa.Const); ok {
			if v, err := strconv.Atoi(c.Value.String()); err == nil {
				constVal = v
				varVal = lhsBinOp.X
				found = true
			}
		} else if c, ok := lhsBinOp.X.(*ssa.Const); ok {
			if v, err := strconv.Atoi(c.Value.String()); err == nil {
				constVal = v
				varVal = lhsBinOp.Y
				found = true
			}
		}

		if found {
			loopVar = varVal
			switch lhsBinOp.Op {
			case token.ADD:
				// (i + k) < len  → equivalent to i < len - k
				lenOffset = -constVal
			case token.SUB:
				// (i - k) < len  → equivalent to i < len + k (rare but safe)
				lenOffset = constVal
			}
			return loopVar, lenOffset, true
		}
	}

	// Fallback: plain i < len (offset 0)
	return loopVar, 0, true
}

// extractIndexOffset checks if indexVal is "loopVar + C"
// returns the constant C and true if successful
func extractIndexOffset(indexVal ssa.Value, loopVar ssa.Value) (int, bool) {
	if indexVal == loopVar {
		return 0, true
	}

	if binOp, ok := indexVal.(*ssa.BinOp); ok {
		switch binOp.Op {
		case token.ADD:
			if binOp.X == loopVar {
				if c, ok := binOp.Y.(*ssa.Const); ok {
					val, err := strconv.Atoi(c.Value.String())
					if err == nil {
						return val, true
					}
				}
			}
			if binOp.Y == loopVar {
				if c, ok := binOp.X.(*ssa.Const); ok {
					val, err := strconv.Atoi(c.Value.String())
					if err == nil {
						return val, true
					}
				}
			}
		case token.SUB:
			if binOp.X == loopVar {
				if c, ok := binOp.Y.(*ssa.Const); ok {
					val, err := strconv.Atoi(c.Value.String())
					if err == nil {
						return -val, true
					}
				}
			}
		}
	}
	return 0, false
}

// decomposeIndex splits an SSA Value into a base value and a constant offset.
func decomposeIndex(v ssa.Value) (ssa.Value, int) {
	if binOp, ok := v.(*ssa.BinOp); ok {
		switch binOp.Op {
		case token.ADD:
			if c, ok := binOp.Y.(*ssa.Const); ok {
				val, err := strconv.Atoi(c.Value.String())
				if err == nil {
					base, offset := decomposeIndex(binOp.X)
					return base, offset + val
				}
			}
			if c, ok := binOp.X.(*ssa.Const); ok {
				val, err := strconv.Atoi(c.Value.String())
				if err == nil {
					base, offset := decomposeIndex(binOp.Y)
					return base, offset + val
				}
			}
		case token.SUB:
			if c, ok := binOp.Y.(*ssa.Const); ok {
				val, err := strconv.Atoi(c.Value.String())
				if err == nil {
					base, offset := decomposeIndex(binOp.X)
					return base, offset - val
				}
			}
		}
	}
	return v, 0
}

// trackSliceBounds recursively follows slice referrers to check for index and boundary violations.
func trackSliceBounds(depth int, sliceCap int, slice ssa.Node, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == maxDepth {
		return
	}
	depth++
	if violations == nil {
		violations = &[]ssa.Instruction{}
	}
	referrers := slice.Referrers()
	if referrers != nil {
		for _, refinstr := range *referrers {
			switch refinstr := refinstr.(type) {
			case *ssa.Slice:
				checkAllSlicesBounds(depth, sliceCap, refinstr, violations, ifs)
				switch refinstr.X.(type) {
				case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
					l, h, maxIdx := extractSliceBounds(refinstr)
					newCap := computeSliceNewCap(l, h, maxIdx, sliceCap)
					trackSliceBounds(depth, newCap, refinstr, violations, ifs)
				}
			case *ssa.IndexAddr:
				indexValue, err := extractIntValue(refinstr.Index.String())
				if err == nil && !isSliceIndexInsideBounds(sliceCap, indexValue) {
					*violations = append(*violations, refinstr)
				}
				indexValue, err = extractIntValueIndexAddr(refinstr, sliceCap)
				if err == nil && !isSliceIndexInsideBounds(sliceCap, indexValue) {
					*violations = append(*violations, refinstr)
				}
			case *ssa.Call:
				if ifref, cond := extractSliceIfLenCondition(refinstr); ifref != nil && cond != nil {
					ifs[*ifref] = cond
				} else {
					parPos := -1
					for pos, arg := range refinstr.Call.Args {
						if a, ok := arg.(*ssa.Slice); ok && a == slice {
							parPos = pos
						}
					}
					if fn, ok := refinstr.Call.Value.(*ssa.Function); ok {
						if len(fn.Params) > parPos && parPos > -1 {
							param := fn.Params[parPos]
							trackSliceBounds(depth, sliceCap, param, violations, ifs)
						}
					}
				}
			}
		}
	}
}

// extractIntValueIndexAddr attempts to derive a constant index value from an IndexAddr by checking its referrers.
func extractIntValueIndexAddr(refinstr *ssa.IndexAddr, sliceCap int) (int, error) {
	base, offset := decomposeIndex(refinstr.Index)
	var sliceIncr int

	// Check Phi node for loop counter patterns
	if p, ok := base.(*ssa.Phi); ok {
		var start int
		var hasStart bool
		var next ssa.Value
		for _, edge := range p.Edges {
			eBase, eOffset := decomposeIndex(edge)
			if c, ok := eBase.(*ssa.Const); ok {
				val, err := strconv.Atoi(c.Value.String())
				if err == nil {
					start = val + eOffset
					hasStart = true
					// Direct check for initial value violation
					if !isSliceIndexInsideBounds(sliceCap+sliceIncr, start+offset) {
						return start + offset, nil
					}
				}
			} else {
				next = edge
			}
		}

		if hasStart && next != nil {
			// Look for loop limit: next < limit or p < limit
			nBase, nOffset := decomposeIndex(next)
			searchVals := []ssa.Value{p, nBase}
			if nBase != next {
				searchVals = append(searchVals, next)
			}

			for _, v := range searchVals {
				if v == nil {
					continue
				}
				refs := v.Referrers()
				if refs == nil {
					continue
				}
				for _, r := range *refs {
					if bin, ok := r.(*ssa.BinOp); ok {
						bound, limit, err := extractBinOpBound(bin)
						if err == nil {
							incr := 0
							if bin.Op == token.LSS {
								incr = -1
							}
							maxV := limit + incr

							// If the limit is on 'next' (i+1 < limit), it still bounds 'i'
							// In 'range n', i reaches n-1.
							// Here we use a heuristic: if we find an upper bound, check it.
							if bound == lowerUnbounded || bound == upperBounded {
								// Correct the max value of 'base' based on where the limit was found
								finalMaxV := maxV
								if v == nBase && nBase != p {
									// if i + nOffset < limit, then i < limit - nOffset
									finalMaxV = maxV - nOffset
								}
								if !isSliceIndexInsideBounds(sliceCap+sliceIncr, finalMaxV+offset) {
									return finalMaxV + offset, nil
								}
							}
						}
					}
				}
			}
		}
	}

	// Falls back to existing queue search for complex dependencies
	queue := []struct {
		val    ssa.Value
		offset int
	}{{base, offset}}
	visited := make(map[ssa.Value]bool)
	depth := 0

	for len(queue) > 0 && depth < maxDepth {
		nextQueue := []struct {
			val    ssa.Value
			offset int
		}{}
		for _, item := range queue {
			if visited[item.val] {
				continue
			}
			visited[item.val] = true

			idxRefs := item.val.Referrers()
			if idxRefs == nil {
				continue
			}
			for _, instr := range *idxRefs {
				switch instr := instr.(type) {
				case *ssa.BinOp:
					switch instr.Op {
					case token.ADD:
						if c, ok := instr.Y.(*ssa.Const); ok {
							val, err := strconv.Atoi(c.Value.String())
							if err == nil {
								nextQueue = append(nextQueue, struct {
									val    ssa.Value
									offset int
								}{instr, item.offset - val})
							}
						}
					case token.SUB:
						if c, ok := instr.Y.(*ssa.Const); ok {
							val, err := strconv.Atoi(c.Value.String())
							if err == nil {
								nextQueue = append(nextQueue, struct {
									val    ssa.Value
									offset int
								}{instr, item.offset + val})
							}
						}
					case token.LSS, token.LEQ, token.GTR, token.GEQ:
						// Already handled by loop counter logic for Phi,
						// but handle other variables here
						if _, ok := item.val.(*ssa.Phi); !ok {
							_, index, err := extractBinOpBound(instr)
							if err != nil {
								continue
							}
							incr := 0
							if instr.Op == token.LSS {
								incr = -1
							}

							if !isSliceIndexInsideBounds(sliceCap+sliceIncr, index+incr+item.offset) {
								return index + item.offset, nil
							}
						}
					}
				}
			}
		}
		queue = nextQueue
		depth++
	}

	return 0, errors.New("no found")
}

// checkAllSlicesBounds validates slice operation boundaries against the known capacity or limit.
func checkAllSlicesBounds(depth int, sliceCap int, slice *ssa.Slice, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == maxDepth {
		return
	}
	depth++
	if violations == nil {
		violations = &[]ssa.Instruction{}
	}
	sliceLow, sliceHigh, sliceMax := extractSliceBounds(slice)
	if sliceMax > 0 {
		if !isThreeIndexSliceInsideBounds(sliceLow, sliceHigh, sliceMax, sliceCap) {
			*violations = append(*violations, slice)
		}
	} else {
		if !isSliceInsideBounds(0, sliceCap, sliceLow, sliceHigh) {
			*violations = append(*violations, slice)
		}
	}
	switch slice.X.(type) {
	case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
		l, h, maxIdx := extractSliceBounds(slice)
		newCap := computeSliceNewCap(l, h, maxIdx, sliceCap)
		trackSliceBounds(depth, newCap, slice, violations, ifs)
	}

	references := slice.Referrers()
	if references == nil {
		return
	}
	for _, ref := range *references {
		switch s := ref.(type) {
		case *ssa.Slice:
			checkAllSlicesBounds(depth, sliceCap, s, violations, ifs)
			switch s.X.(type) {
			case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
				l, h, maxIdx := extractSliceBounds(s)
				newCap := computeSliceNewCap(l, h, maxIdx, sliceCap)
				trackSliceBounds(depth, newCap, s, violations, ifs)
			}
		}
	}
}

func extractSliceIfLenCondition(call *ssa.Call) (*ssa.If, *ssa.BinOp) {
	if builtInLen, ok := call.Call.Value.(*ssa.Builtin); ok {
		if builtInLen.Name() == "len" {
			refs := []ssa.Instruction{}
			if call.Referrers() != nil {
				refs = append(refs, *call.Referrers()...)
			}
			depth := 0
			for len(refs) > 0 && depth < maxDepth {
				newrefs := []ssa.Instruction{}
				for _, ref := range refs {
					if binop, ok := ref.(*ssa.BinOp); ok {
						binoprefs := binop.Referrers()
						for _, ref := range *binoprefs {
							if ifref, ok := ref.(*ssa.If); ok {
								return ifref, binop
							}
							newrefs = append(newrefs, ref)
						}
					}
				}
				refs = newrefs
				depth++
			}

		}
	}
	return nil, nil
}

// computeSliceNewCap determines the resulting capacity or limit of a slice after a re-slicing operation.
func computeSliceNewCap(l, h, maxIdx, oldCap int) int {
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

func invBound(bound bound) bound {
	switch bound {
	case lowerUnbounded:
		return upperUnbounded
	case upperUnbounded:
		return lowerUnbounded
	case upperBounded:
		return unbounded
	case unbounded:
		return upperBounded
	case bounded:
		return bounded
	default:
		return unbounded
	}
}

var errExtractBinOp = fmt.Errorf("unable to extract constant from binop")

func extractBinOpBound(binop *ssa.BinOp) (bound, int, error) {
	if binop.X != nil {
		if x, ok := binop.X.(*ssa.Const); ok {
			if x.Value == nil {
				return lowerUnbounded, 0, errExtractBinOp
			}
			value, err := strconv.Atoi(x.Value.String())
			if err != nil {
				return lowerUnbounded, value, err
			}
			switch binop.Op {
			case token.LSS, token.LEQ:
				return upperUnbounded, value, nil
			case token.GTR, token.GEQ:
				return lowerUnbounded, value, nil
			case token.EQL:
				return bounded, value, nil
			case token.NEQ:
				return unbounded, value, nil
			}
		}
	}
	if binop.Y != nil {
		if y, ok := binop.Y.(*ssa.Const); ok {
			if y.Value == nil {
				return lowerUnbounded, 0, errExtractBinOp
			}
			value, err := strconv.Atoi(y.Value.String())
			if err != nil {
				return lowerUnbounded, value, err
			}
			switch binop.Op {
			case token.LSS, token.LEQ:
				return lowerUnbounded, value, nil
			case token.GTR, token.GEQ:
				return upperUnbounded, value, nil
			case token.EQL:
				return bounded, value, nil
			case token.NEQ:
				return unbounded, value, nil
			}
		}
	}
	return lowerUnbounded, 0, errExtractBinOp
}

func isSliceIndexInsideBounds(h int, index int) bool {
	return (0 <= index && index < h)
}

// isSliceInsideBounds checks if the requested slice range is within the parent slice's boundaries.
func isSliceInsideBounds(l, h int, cl, ch int) bool {
	return (l <= cl && h >= ch) && (l <= ch && h >= cl)
}

// isThreeIndexSliceInsideBounds validates the boundaries and capacity of a 3-index slice (s[i:j:k]).
func isThreeIndexSliceInsideBounds(l, h, maxIdx int, oldCap int) bool {
	return l >= 0 && h >= l && maxIdx >= h && maxIdx <= oldCap
}

// extractSliceBounds extracts the lower, upper, and (optional) max capacity indices from an ssa.Slice instruction.
func extractSliceBounds(slice *ssa.Slice) (int, int, int) {
	var low int
	if slice.Low != nil {
		l, err := extractIntValue(slice.Low.String())
		if err == nil {
			low = l
		}
	}
	var high int
	if slice.High != nil {
		h, err := extractIntValue(slice.High.String())
		if err == nil {
			high = h
		}
	}
	var maxIdx int
	if slice.Max != nil {
		m, err := extractIntValue(slice.Max.String())
		if err == nil {
			maxIdx = m
		}
	}
	return low, high, maxIdx
}

// extractIntValue attempts to parse a constant integer value from an SSA value string representation.
func extractIntValue(value string) (int, error) {
	if i, err := extractIntValuePhi(value); err == nil {
		return i, nil
	}

	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid value: %s", value)
	}
	if parts[1] != "int" {
		return 0, fmt.Errorf("invalid value: %s", value)
	}
	return strconv.Atoi(parts[0])
}

// extractSliceCapFromAlloc parses the initial capacity of a slice from its allocation instruction string.
func extractSliceCapFromAlloc(instr string) (int, error) {
	re := regexp.MustCompile(`new \[(\d+)\].*`)
	var sliceCap int
	matches := re.FindAllStringSubmatch(instr, -1)
	if matches == nil {
		return sliceCap, errors.New("no slice cap found")
	}

	if len(matches) > 0 {
		m := matches[0]
		if len(m) > 1 {
			return strconv.Atoi(m[1])
		}
	}

	return 0, errors.New("no slice cap found")
}

// extractIntValuePhi parses an integer value from an SSA Phi instruction string representation.
func extractIntValuePhi(value string) (int, error) {
	re := regexp.MustCompile(`phi \[.+: (\d+):.+, .*\].*`)
	var sliceCap int
	matches := re.FindAllStringSubmatch(value, -1)
	if matches == nil {
		return sliceCap, fmt.Errorf("invalid value: %s", value)
	}

	if len(matches) > 0 {
		m := matches[0]
		if len(m) > 1 {
			return strconv.Atoi(m[1])
		}
	}

	return 0, fmt.Errorf("invalid value: %s", value)
}

// extractArrayAllocValue parses the constant length of an array allocation from its type string.
func extractArrayAllocValue(value string) (int, error) {
	re := regexp.MustCompile(`.*\[(\d+)\].*`)
	var sliceCap int
	matches := re.FindAllStringSubmatch(value, -1)
	if matches == nil {
		return sliceCap, fmt.Errorf("invalid value: %s", value)
	}

	if len(matches) > 0 {
		m := matches[0]
		if len(m) > 1 {
			return strconv.Atoi(m[1])
		}
	}

	return 0, fmt.Errorf("invalid value: %s", value)
}
