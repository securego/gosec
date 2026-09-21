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
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

var errNoFound = errors.New("no found")

type bound int

const (
	lowerUnbounded bound = iota
	upperUnbounded
	unbounded
	upperBounded
	bounded
)

func newSliceBoundsAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runSliceBounds,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

type valOffset struct {
	val    ssa.Value
	offset int
}

type sliceBoundsState struct {
	*BaseAnalyzerState
	trackCache map[trackCacheKey]*trackCacheValue
	valQueue   []valOffset
}

var (
	trackValuePool = sync.Pool{
		New: func() any {
			return &trackCacheValue{
				violations: make([]ssa.Instruction, 0, 4),
				ifs:        make(map[ssa.If]*ssa.BinOp),
			}
		},
	}
	trackMapPool = sync.Pool{
		New: func() any {
			return make(map[trackCacheKey]*trackCacheValue, 32)
		},
	}
)

type trackCacheKey struct {
	node     ssa.Node
	sliceCap int
}

type trackCacheValue struct {
	violations []ssa.Instruction
	ifs        map[ssa.If]*ssa.BinOp
}

func newSliceBoundsState(pass *analysis.Pass) *sliceBoundsState {
	return &sliceBoundsState{
		BaseAnalyzerState: NewBaseState(pass),
		trackCache:        trackMapPool.Get().(map[trackCacheKey]*trackCacheValue),
		valQueue:          make([]valOffset, 0, 32),
	}
}

func (s *sliceBoundsState) Release() {
	if s.trackCache != nil {
		for _, res := range s.trackCache {
			if res != nil {
				res.Reset()
				trackValuePool.Put(res)
			}
		}
		clear(s.trackCache)
		trackMapPool.Put(s.trackCache)
		s.trackCache = nil
	}
	s.BaseAnalyzerState.Release()
}

func (s *sliceBoundsState) acquireTrackCacheValue() *trackCacheValue {
	res := trackValuePool.Get().(*trackCacheValue)
	res.Reset()
	return res
}

func (s *sliceBoundsState) releaseTrackCacheValue(res *trackCacheValue) {
	if res != nil {
		res.Reset()
		trackValuePool.Put(res)
	}
}

func (v *trackCacheValue) Reset() {
	v.violations = v.violations[:0]
	clear(v.ifs)
}

func (s *sliceBoundsState) Reset() {
	s.BaseAnalyzerState.Reset()
	for _, res := range s.trackCache {
		if res != nil {
			s.releaseTrackCacheValue(res)
		}
	}
	clear(s.trackCache)
}

func runSliceBounds(pass *analysis.Pass) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = nil
			err = nil // Return nil error to allow other analyzers to continue
		}
	}()

	ssaResult, err := ssautil.GetSSAResult(pass)
	if err != nil {
		return nil, err
	}

	state := newSliceBoundsState(pass)
	defer state.Release()
	issues := map[ssa.Instruction]*issue.Issue{}
	ifs := map[ssa.If]*ssa.BinOp{}
	var violations []ssa.Instruction
	for _, mcall := range ssaResult.SSA.SrcFuncs {
		state.Reset()
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				switch instr := instr.(type) {
				case *ssa.Alloc:
					if sliceCap, ok := extractArrayLen(instr.Type()); ok {
						allocRefs := instr.Referrers()
						if allocRefs == nil {
							break
						}
						for _, refInstr := range *allocRefs {
							if slice, ok := refInstr.(*ssa.Slice); ok {
								if slice.Parent() != nil {
									l, h, maxIdx := GetSliceBounds(slice)
									violations = violations[:0]
									if maxIdx > 0 {
										if !isThreeIndexSliceInsideBounds(l, h, maxIdx, sliceCap) {
											violations = append(violations, slice)
										}
									} else {
										if !isSliceInsideBounds(0, sliceCap, l, h) {
											violations = append(violations, slice)
										}
									}
									newCap := ComputeSliceNewCap(l, h, maxIdx, sliceCap)
									state.trackSliceBounds(0, newCap, slice, &violations, ifs)
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
											// Skip IndexAddr that directly accesses the original array (not the slice)
											if s.X == instr {
												continue
											}
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
					if instr.X == nil {
						break
					}
					switch indexInstr := instr.X.(type) {
					case *ssa.Const:
						if _, ok := indexInstr.Type().Underlying().(*types.Slice); ok {
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
							if arrayLen, ok := extractArrayLen(indexInstr.Type()); ok {
								indexValue, err := state.extractIntValueIndexAddr(instr, arrayLen)
								if err == nil && !isSliceIndexInsideBounds(arrayLen, indexValue) {
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

		// Guard against nil Block()
		ifBlock := ifref.Block()
		if ifBlock == nil {
			continue
		}
		for i, block := range ifBlock.Succs {
			if i == 1 {
				bound = invBound(bound)
			}

			// Inequality guards need slice identity and index-value checks. Walk
			// every issue in the CFG region dominated by this successor so an
			// outer len() guard also applies after nested branch joins.
			if bound == upperUnbounded || bound == unbounded {
				guardedSlice := lenConditionSlice(binop)
				minLen, hasMinLen := minimumLenForBranch(binop, i)
				if guardedSlice != nil && hasMinLen {
					for instr := range issues {
						instrBlock := instr.Block()
						if instrBlock == nil || !block.Dominates(instrBlock) {
							continue
						}
						switch tinstr := instr.(type) {
						case *ssa.Slice:
							if tinstr.X == guardedSlice && sliceWithinAssertedLen(tinstr, minLen) {
								delete(issues, instr)
							}
						case *ssa.IndexAddr:
							if tinstr.X == guardedSlice {
								if indexValue, ok := GetConstantInt64(tinstr.Index); ok &&
									isSliceIndexInsideBounds(minLen, int(indexValue)) {
									delete(issues, instr)
								}
							}
						}
					}
				}
			}

			var processBlock func(block *ssa.BasicBlock, depth int)
			processBlock = func(block *ssa.BasicBlock, depth int) {
				if depth == MaxDepth {
					return
				}
				depth++
				for _, instr := range block.Instrs {
					if _, ok := issues[instr]; ok {
						switch bound {
						case lowerUnbounded:
							break
						case upperUnbounded, unbounded:
							// Handled above with branch dominance, slice identity,
							// and a proven minimum length.
						case upperBounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								_, _, m := GetSliceBounds(tinstr)
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
									if indexValue, ok := GetConstantInt64(tinstr.Index); ok {
										if isSliceIndexInsideBounds(value, int(indexValue)) {
											delete(issues, instr)
										}
									}
								}
							}
						case bounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								// Equality only establishes a length in the then branch.
								if i == 0 && sliceWithinAssertedLen(tinstr, assertedLen(binop, value)) {
									delete(issues, instr)
								}
							case *ssa.IndexAddr:
								// invBound maps bounded to itself, so the "else" successor
								// is walked with the same bound and value even though it
								// only proves the length is *not* the asserted one. Trust
								// the asserted length in the "then" successor alone.
								if indexValue, ok := GetConstantInt64(tinstr.Index); ok {
									if i == 0 && isSliceIndexInsideBounds(assertedLen(binop, value), int(indexValue)) {
										delete(issues, instr)
									}
								}
							}
						}
					} else if nestedIfInstr, ok := instr.(*ssa.If); ok {
						// Guard against nil Block()
						if nestedIfBlock := nestedIfInstr.Block(); nestedIfBlock != nil {
							for _, nestedBlock := range nestedIfBlock.Succs {
								processBlock(nestedBlock, depth)
							}
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
	if binop == nil {
		return nil, 0, false
	}
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
		if val, ok := GetConstantInt64(rhsBinOp.Y); ok {
			constVal = int(val)
			foundConst = true
		} else if val, ok := GetConstantInt64(rhsBinOp.X); ok {
			constVal = int(val)
			foundConst = true
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

		if val, ok := GetConstantInt64(lhsBinOp.Y); ok {
			constVal = int(val)
			varVal = lhsBinOp.X
			found = true
		} else if val, ok := GetConstantInt64(lhsBinOp.X); ok {
			constVal = int(val)
			varVal = lhsBinOp.Y
			found = true
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
				if val, ok := GetConstantInt64(binOp.Y); ok {
					return int(val), true
				}
			}
			if binOp.Y == loopVar {
				if val, ok := GetConstantInt64(binOp.X); ok {
					return int(val), true
				}
			}
		case token.SUB:
			if binOp.X == loopVar {
				if val, ok := GetConstantInt64(binOp.Y); ok {
					return int(-val), true
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
			if val, ok := GetConstantInt64(binOp.Y); ok {
				base, offset := decomposeIndex(binOp.X)
				return base, offset + int(val)
			}
			if val, ok := GetConstantInt64(binOp.X); ok {
				base, offset := decomposeIndex(binOp.Y)
				return base, offset + int(val)
			}
		case token.SUB:
			if val, ok := GetConstantInt64(binOp.Y); ok {
				base, offset := decomposeIndex(binOp.X)
				return base, offset - int(val)
			}
		}
	}
	return v, 0
}

// trackSliceBounds recursively follows slice referrers to check for index and boundary violations.
func (s *sliceBoundsState) trackSliceBounds(depth int, sliceCap int, slice ssa.Node, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == MaxDepth {
		return
	}
	depth++

	key := trackCacheKey{slice, sliceCap}
	if res, ok := s.trackCache[key]; ok {
		if res == nil { // visiting
			return
		}
		*violations = append(*violations, res.violations...)
		maps.Copy(ifs, res.ifs)
		return
	}
	s.trackCache[key] = nil // mark as visiting

	res := s.acquireTrackCacheValue()
	localViolations := &res.violations
	localIfs := res.ifs

	if violations == nil {
		violations = &[]ssa.Instruction{}
	}
	referrers := slice.Referrers()
	if referrers != nil {
		for _, refinstr := range *referrers {
			switch refinstr := refinstr.(type) {
			case *ssa.Slice:
				s.checkAllSlicesBounds(depth, sliceCap, refinstr, localViolations, localIfs)
				switch refinstr.X.(type) {
				case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
					l, h, maxIdx := GetSliceBounds(refinstr)
					newCap := ComputeSliceNewCap(l, h, maxIdx, sliceCap)
					s.trackSliceBounds(depth, newCap, refinstr, localViolations, localIfs)
				}
			case *ssa.IndexAddr:
				if indexValue, ok := GetConstantInt64(refinstr.Index); ok && !isSliceIndexInsideBounds(sliceCap, int(indexValue)) {
					*localViolations = append(*localViolations, refinstr)
				}
				indexValue, err := s.extractIntValueIndexAddr(refinstr, sliceCap)
				if err == nil && !isSliceIndexInsideBounds(sliceCap, indexValue) {
					*localViolations = append(*localViolations, refinstr)
				}
			case *ssa.Call:
				if ifref, cond := extractSliceIfLenCondition(refinstr); ifref != nil && cond != nil {
					localIfs[*ifref] = cond
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
							s.trackSliceBounds(depth, sliceCap, param, localViolations, localIfs)
						}
					}
				}
			}
		}
	}

	*violations = append(*violations, *localViolations...)
	maps.Copy(ifs, localIfs)
	s.trackCache[key] = res
}

func (s *sliceBoundsState) extractIntValueIndexAddr(refinstr *ssa.IndexAddr, sliceCap int) (int, error) {
	base, offset := decomposeIndex(refinstr.Index)
	var sliceIncr int

	canNormalizeToBase := func(bin *ssa.BinOp) bool {
		if bin == nil || refinstr == nil {
			return false
		}
		binBlock := bin.Block()
		idxBlock := refinstr.Block()
		if binBlock == nil || idxBlock == nil {
			return false
		}
		if binBlock != idxBlock {
			return true
		}
		binPos := -1
		idxPos := -1
		for i, ins := range binBlock.Instrs {
			if ins == bin {
				binPos = i
			}
			if ins == refinstr {
				idxPos = i
			}
			if binPos >= 0 && idxPos >= 0 {
				break
			}
		}
		if binPos < 0 || idxPos < 0 {
			return false
		}
		return binPos < idxPos
	}

	// Case 1: Base is a constant (e.g., s[0+3])
	if val, ok := GetConstantInt64(base); ok {
		finalIdx := int(val) + offset
		if !isSliceIndexInsideBounds(sliceCap+sliceIncr, finalIdx) {
			return finalIdx, nil
		}
		// Constant index is within bounds; avoid BFS exploring shared SSA constant referrers
		return 0, errNoFound
	}

	// Case 2: Base is a Phi node (loop counter)
	if p, ok := base.(*ssa.Phi); ok {
		var start int
		var hasStart bool
		var next ssa.Value
		for _, edge := range p.Edges {
			// Guard against nil edges
			if edge == nil {
				continue
			}
			eBase, eOffset := decomposeIndex(edge)
			if val, ok := GetConstantInt64(eBase); ok {
				start = int(val) + eOffset
				hasStart = true
				// Direct check for initial value violation
				if !isSliceIndexInsideBounds(sliceCap+sliceIncr, start+offset) {
					return start + offset, nil
				}
			} else {
				next = edge
			}
		}

		if hasStart && next != nil {
			// Look for loop limit: next < limit or p < limit
			nBase, nOffset := decomposeIndex(next)
			var searchVals [3]ssa.Value
			searchVals[0] = p
			searchVals[1] = nBase
			numVals := 2
			if nBase != next {
				searchVals[2] = next
				numVals = 3
			}

			for _, v := range searchVals[:numVals] {
				if v == nil {
					continue
				}
				refs := v.Referrers()
				if refs == nil {
					continue
				}
				for _, r := range *refs {
					if bin, ok := r.(*ssa.BinOp); ok {
						// Check for constant bound
						bound, limit, err := extractBinOpBound(bin)
						if err == nil {
							incr := 0
							if bin.Op == token.LSS {
								incr = -1
							}
							maxV := limit + incr

							// If the limit is found on an incremented value (next or nBase != p),
							// normalize it back to the base loop variable before applying index offset.
							boundAdjust := 0
							if (v == next && base != next && canNormalizeToBase(bin)) || (v == nBase && nBase != p && base != nBase) {
								boundAdjust = -nOffset
							}

							if bound == lowerUnbounded || bound == upperBounded {
								finalMaxV := maxV + boundAdjust
								if !isSliceIndexInsideBounds(sliceCap+sliceIncr, finalMaxV+offset) {
									return finalMaxV + offset, nil
								}
							}
						} else if _, off, ok := extractLenBound(bin); ok {
							// Check for length bound (e.g. i < len(s) + off)
							// Here the limit is effectively sliceCap
							limit := sliceCap
							incr := -1 // extractLenBound only handles LSS for now
							maxV := limit + off + incr

							boundAdjust := 0
							if (v == next && base != next && canNormalizeToBase(bin)) || (v == nBase && nBase != p && base != nBase) {
								boundAdjust = -nOffset
							}
							finalMaxV := maxV + boundAdjust
							if !isSliceIndexInsideBounds(sliceCap+sliceIncr, finalMaxV+offset) {
								return finalMaxV + offset, nil
							}
						}
					}
				}
			}
		}
	}

	// Falls back to existing queue search for complex dependencies
	s.valQueue = s.valQueue[:0]
	s.valQueue = append(s.valQueue, valOffset{base, offset})
	clear(s.Visited)
	depth := 0

	head := 0
	for head < len(s.valQueue) && depth < MaxDepth {
		levelSize := len(s.valQueue) - head
		for i := 0; i < levelSize; i++ {
			item := s.valQueue[head]
			head++
			if s.Visited[item.val] {
				continue
			}
			s.Visited[item.val] = true

			idxRefs := item.val.Referrers()
			if idxRefs == nil {
				continue
			}
			for _, instr := range *idxRefs {
				switch instr := instr.(type) {
				case *ssa.BinOp:
					switch instr.Op {
					case token.ADD:
						if val, ok := GetConstantInt64(instr.Y); ok {
							s.valQueue = append(s.valQueue, valOffset{instr, item.offset - int(val)})
						}
					case token.SUB:
						if val, ok := GetConstantInt64(instr.Y); ok {
							s.valQueue = append(s.valQueue, valOffset{instr, item.offset + int(val)})
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
		depth++
	}

	return 0, errNoFound
}

// checkAllSlicesBounds validates slice operation boundaries against the known capacity or limit.
func (s *sliceBoundsState) checkAllSlicesBounds(depth int, sliceCap int, slice *ssa.Slice, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == MaxDepth {
		return
	}
	depth++
	if violations == nil {
		violations = &[]ssa.Instruction{}
	}
	sliceLow, sliceHigh, sliceMax := GetSliceBounds(slice)
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
		l, h, maxIdx := GetSliceBounds(slice)
		newCap := ComputeSliceNewCap(l, h, maxIdx, sliceCap)
		s.trackSliceBounds(depth, newCap, slice, violations, ifs)
	}

	references := slice.Referrers()
	if references == nil {
		return
	}
	for _, ref := range *references {
		switch r := ref.(type) {
		case *ssa.Slice:
			s.checkAllSlicesBounds(depth, sliceCap, r, violations, ifs)
			switch r.X.(type) {
			case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
				l, h, maxIdx := GetSliceBounds(r)
				newCap := ComputeSliceNewCap(l, h, maxIdx, sliceCap)
				s.trackSliceBounds(depth, newCap, r, violations, ifs)
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
			for len(refs) > 0 && depth < MaxDepth {
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

// lenConditionSlice returns the slice whose len() participates in binop.
// Constant +/- offsets around len() are handled by decomposeIndex.
func lenConditionSlice(binop *ssa.BinOp) ssa.Value {
	if binop == nil {
		return nil
	}
	for _, operand := range []ssa.Value{binop.X, binop.Y} {
		if _, isConst := operand.(*ssa.Const); isConst {
			continue
		}
		base, _ := decomposeIndex(operand)
		call, ok := base.(*ssa.Call)
		if !ok {
			continue
		}
		builtin, ok := call.Call.Value.(*ssa.Builtin)
		if !ok || builtin.Name() != "len" || len(call.Call.Args) != 1 {
			continue
		}
		return call.Call.Args[0]
	}
	return nil
}

// minimumLenForBranch returns the minimum slice length guaranteed by a
// constant comparison involving len(slice) in the selected successor.
// Comparisons that do not prove a useful lower bound are rejected.
func minimumLenForBranch(binop *ssa.BinOp, successor int) (int, bool) {
	if binop == nil || (successor != 0 && successor != 1) {
		return 0, false
	}

	op := binop.Op
	var lengthExpr ssa.Value
	var threshold int64

	if value, ok := GetConstantInt64(binop.Y); ok {
		lengthExpr = binop.X
		threshold = value
	} else if value, ok := GetConstantInt64(binop.X); ok {
		lengthExpr = binop.Y
		threshold = value
		op = reverseComparison(op)
	} else {
		return 0, false
	}

	base, offset := decomposeIndex(lengthExpr)
	call, ok := base.(*ssa.Call)
	if !ok {
		return 0, false
	}
	builtin, ok := call.Call.Value.(*ssa.Builtin)
	if !ok || builtin.Name() != "len" || len(call.Call.Args) != 1 {
		return 0, false
	}

	threshold -= int64(offset)
	if successor == 1 {
		op = invertComparison(op)
	}

	var minLen int64
	switch op {
	case token.GTR:
		if threshold == int64(^uint64(0)>>1) {
			return 0, false
		}
		minLen = threshold + 1
	case token.GEQ:
		minLen = threshold
	case token.NEQ:
		// Only != 0 proves a positive lower bound.
		if threshold != 0 {
			return 0, false
		}
		minLen = 1
	default:
		return 0, false
	}

	if minLen < 0 {
		minLen = 0
	}
	maxInt := int64(^uint(0) >> 1)
	if minLen > maxInt {
		return 0, false
	}
	return int(minLen), true
}

func reverseComparison(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.LEQ:
		return token.GEQ
	case token.GTR:
		return token.LSS
	case token.GEQ:
		return token.LEQ
	default:
		return op
	}
}

func invertComparison(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GEQ
	case token.LEQ:
		return token.GTR
	case token.GTR:
		return token.LEQ
	case token.GEQ:
		return token.LSS
	case token.EQL:
		return token.NEQ
	case token.NEQ:
		return token.EQL
	default:
		return op
	}
}

var errExtractBinOp = errors.New("unable to extract constant from binop")

func extractBinOpBound(binop *ssa.BinOp) (bound, int, error) {
	if binop == nil {
		return lowerUnbounded, 0, errExtractBinOp
	}
	if binop.X != nil {
		if x, ok := binop.X.(*ssa.Const); ok {
			if x.Value == nil {
				return lowerUnbounded, 0, errExtractBinOp
			}
			val, ok := constant.Int64Val(x.Value)
			if !ok {
				return lowerUnbounded, 0, errExtractBinOp
			}
			value := int(val)
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
			val, ok := constant.Int64Val(y.Value)
			if !ok {
				return lowerUnbounded, 0, errExtractBinOp
			}
			value := int(val)
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

// assertedLen returns the slice length asserted by an equality comparison whose
// constant side is value. The compared expression is usually len(s) itself, but
// it may carry a constant offset (e.g. "len(s) - 1 == 1" asserts a length of 2),
// in which case the offset has to be undone to recover the length.
func assertedLen(binop *ssa.BinOp, value int) int {
	if binop == nil {
		return value
	}
	for _, operand := range []ssa.Value{binop.X, binop.Y} {
		if _, isConst := operand.(*ssa.Const); isConst {
			continue
		}
		if _, offset := decomposeIndex(operand); offset != 0 {
			return value - offset
		}
	}
	return value
}

// sliceWithinAssertedLen only clears findings when every explicit bound is
// constant and fits within the guaranteed length (and therefore capacity).
func sliceWithinAssertedLen(slice *ssa.Slice, length int) bool {
	bounds := []int{0, length, length}
	for i, value := range []ssa.Value{slice.Low, slice.High, slice.Max} {
		if value == nil {
			continue
		}
		bound, ok := GetConstantInt64(value)
		if !ok || bound < 0 || bound > int64(length) {
			return false
		}
		bounds[i] = int(bound)
	}
	return isThreeIndexSliceInsideBounds(bounds[0], bounds[1], bounds[2], length)
}

func isSliceIndexInsideBounds(h int, index int) bool {
	return (0 <= index && index < h)
}

// extractArrayLen attempts to determine the length of an array type, stripping pointers if necessary.
func extractArrayLen(t types.Type) (int, bool) {
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if arr, ok := t.Underlying().(*types.Array); ok {
		return int(arr.Len()), true
	}
	return 0, false
}
