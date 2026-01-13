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
	"cmp"
	"fmt"
	"go/constant"
	"go/token"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

const defaultIssueDescription = "Use of hardcoded IV/nonce for encryption"

// tracked holds the function name as key, the number of arguments that the function accepts,
// and the index of the argument that is the nonce/IV.
// Example: "crypto/cipher.NewCBCEncrypter": {2, 1} means the function accepts 2 arguments,
// and the nonce arg is at index 1 (the second argument).
var tracked = map[string][]int{
	"(crypto/cipher.AEAD).Seal":     {4, 1},
	"crypto/cipher.NewCBCEncrypter": {2, 1},
	"crypto/cipher.NewCFBEncrypter": {2, 1},
	"crypto/cipher.NewCTR":          {2, 1},
	"crypto/cipher.NewOFB":          {2, 1},
}

var dynamicFuncs = map[string]bool{
	"crypto/rand.Read": true,
	"io.ReadFull":      true,
}

var dynamicPkgs = map[string]bool{
	"crypto/rand": true,
	"io":          true,
}

var cipherPkgPrefixes = []string{
	"crypto/cipher",
	"crypto/aes",
}

const (
	statusVisiting = 1 << 0
	statusHard     = 1 << 1
	statusDyn      = 1 << 2
)

func newHardCodedNonce(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runHardCodedNonce,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runHardCodedNonce(pass *analysis.Pass) (any, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, err
	}

	state := newAnalysisState(pass, ssaResult.SSA.SrcFuncs)

	args := state.getInitialArgs(tracked)
	var issues []*issue.Issue
	for _, argInfo := range args {
		i, err := state.raiseIssue(argInfo.val, "", make(map[ssa.Value]bool), argInfo.instr)
		if err != nil {
			return issues, fmt.Errorf("raising issue error: %w", err)
		}
		issues = append(issues, i...)
	}
	return issues, nil
}

type analysisState struct {
	pass              *analysis.Pass
	ssaFuncs          []*ssa.Function
	usageCache        map[ssa.Value]uint8
	funcCache         map[*ssa.Function]bool
	visitedFuncs      map[*ssa.Function]bool
	callerMap         map[string][]*ssa.Call
	bufferLenCache    map[ssa.Value]int64
	funcResolutionMap map[ssa.Value]bool
	rangeCache        map[ssa.Value]ByteRange
	depth             int
	analyzer          *RangeAnalyzer
}

type ssaValueAndInstr struct {
	val   ssa.Value
	instr ssa.Instruction
}

func newAnalysisState(pass *analysis.Pass, funcs []*ssa.Function) *analysisState {
	s := &analysisState{
		pass:              pass,
		ssaFuncs:          funcs,
		usageCache:        make(map[ssa.Value]uint8),
		funcCache:         make(map[*ssa.Function]bool),
		visitedFuncs:      make(map[*ssa.Function]bool),
		callerMap:         BuildCallerMap(funcs),
		bufferLenCache:    make(map[ssa.Value]int64),
		funcResolutionMap: make(map[ssa.Value]bool),
		rangeCache:        make(map[ssa.Value]ByteRange),
		analyzer:          NewRangeAnalyzer(),
	}
	return s
}

// getInitialArgs returns a list of arguments and their corresponding instructions
// for all call sites identified in the tracked map.
func (s *analysisState) getInitialArgs(tracked map[string][]int) []ssaValueAndInstr {
	var result []ssaValueAndInstr
	for _, f := range s.ssaFuncs {
		for _, b := range f.Blocks {
			for _, i := range b.Instrs {
				if c, ok := i.(*ssa.Call); ok {
					if c.Call.IsInvoke() {
						// Handle interface method calls (e.g. (crypto/cipher.AEAD).Seal)
						name := c.Call.Method.FullName()
						if info, ok := tracked[name]; ok {
							if len(c.Call.Args) == info[0] {
								result = append(result, ssaValueAndInstr{
									val:   c.Call.Args[info[1]],
									instr: c,
								})
							}
						}
						continue
					}

					// Handle function calls (direct or indirect)
					clear(s.funcResolutionMap)
					var funcs []*ssa.Function
					s.resolveFuncs(c.Call.Value, &funcs)
					for _, fn := range funcs {
						name := fn.String()
						if info, ok := tracked[name]; ok {
							if len(c.Call.Args) == info[0] {
								result = append(result, ssaValueAndInstr{
									val:   c.Call.Args[info[1]],
									instr: c,
								})
								break
							}
							continue
						}
						if fn.Pkg != nil && fn.Pkg.Pkg != nil {
							name = fn.Pkg.Pkg.Path() + "." + fn.Name()
							if info, ok := tracked[name]; ok {
								if len(c.Call.Args) == info[0] {
									result = append(result, ssaValueAndInstr{
										val:   c.Call.Args[info[1]],
										instr: c,
									})
									break
								}
							}
						}
					}
				}
			}
		}
	}
	return result
}

// raiseIssue recursively analyzes the usage of a value and returns a list of issues
// if it's found to be hardcoded or otherwise insecure.
func (s *analysisState) raiseIssue(val ssa.Value, issueDescription string,
	visitedParams map[ssa.Value]bool, fromInstr ssa.Instruction,
) ([]*issue.Issue, error) {
	if visitedParams[val] {
		return nil, nil
	}
	visitedParams[val] = true

	res := s.analyzeUsage(val)
	foundDyn := res&statusDyn != 0

	if foundDyn {
		if s.allTaintedEventsCovered(val, fromInstr) {
			return nil, nil
		}
	}

	if issueDescription == "" {
		issueDescription = defaultIssueDescription
	}

	var allIssues []*issue.Issue
	switch v := val.(type) {
	case *ssa.Slice:
		if s.isHardcoded(v.X) {
			issueDescription += " by passing hardcoded slice/array"
		}
		return s.raiseIssue(v.X, issueDescription, visitedParams, fromInstr)
	case *ssa.UnOp:
		if v.Op == token.MUL {
			if s.isHardcoded(v.X) {
				issueDescription += " by passing pointer which points to hardcoded variable"
			}
			return s.raiseIssue(v.X, issueDescription, visitedParams, fromInstr)
		}
	case *ssa.Convert:
		if v.Type().String() == "[]byte" && v.X.Type().String() == "string" {
			if s.isHardcoded(v.X) {
				issueDescription += " by passing converted string"
			}
		}
		return s.raiseIssue(v.X, issueDescription, visitedParams, fromInstr)
	case *ssa.Const:
		issueDescription += " by passing hardcoded constant"
		allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
	case *ssa.Global:
		issueDescription += " by passing hardcoded global"
		allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
	case *ssa.Alloc:
		switch v.Comment {
		case "slicelit":
			issueDescription += " by passing hardcoded slice literal"
			allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
		case "makeslice":
			res := s.analyzeUsage(v)
			foundHard := res&statusHard != 0
			if foundHard {
				if s.allTaintedEventsCovered(v, fromInstr) {
					return nil, nil
				}
				issueDescription += " by passing a buffer from make modified with hardcoded values"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			} else {
				if s.allTaintedEventsCovered(v, fromInstr) {
					return nil, nil
				}
				issueDescription += " by passing a zeroed buffer from make"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			}
		default:
			// Ensure we trace the specific Store that tainted this Alloc
			if refs := v.Referrers(); refs != nil {
				for _, ref := range *refs {
					if store, ok := ref.(*ssa.Store); ok && store.Addr == v {
						if s.isHardcoded(store.Val) {
							issues, err := s.raiseIssue(store.Val, issueDescription, visitedParams, fromInstr)
							if err != nil {
								return nil, err
							}
							allIssues = append(allIssues, issues...)
						}
					}
				}
			}
		}
	case *ssa.MakeSlice:
		res := s.analyzeUsage(v)
		foundDyn := res&statusDyn != 0
		foundHard := res&statusHard != 0
		if foundHard {
			issueDescription += " by passing a buffer from make modified with hardcoded values"
			allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
		} else if !foundDyn {
			issueDescription += " by passing a zeroed buffer from make"
			allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
		}
	case *ssa.Call:
		if s.isHardcoded(v) {
			issueDescription += " by passing a value from function which returns hardcoded value"
			allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
		}
	case *ssa.Parameter:
		if v.Parent() != nil {
			parentName := v.Parent().String()
			paramIdx := -1
			for i, p := range v.Parent().Params {
				if p == v {
					paramIdx = i
					break
				}
			}
			if paramIdx != -1 {
				numParams := len(v.Parent().Params)
				issueDescription += " by passing a parameter to a function and"
				if callers, ok := s.callerMap[parentName]; ok {
					for _, c := range callers {
						if len(c.Call.Args) == numParams {
							issues, _ := s.raiseIssue(c.Call.Args[paramIdx], issueDescription, visitedParams, c)
							allIssues = append(allIssues, issues...)
						}
					}
				}
			}
		}
	}
	return allIssues, nil
}

// isHardcoded determines if a value is derived from a hardcoded constant
// or specific patterns (e.g. "slicelit" comment on Alloc).
func (s *analysisState) isHardcoded(val ssa.Value) bool {
	if s.depth > MaxDepth {
		return false
	}
	s.depth++
	defer func() { s.depth-- }()

	switch v := val.(type) {
	case *ssa.Const, *ssa.Global:
		return true
	case *ssa.Convert:
		return s.isHardcoded(v.X)
	case *ssa.Slice:
		return s.isHardcoded(v.X)
	case *ssa.Alloc:
		if v.Comment == "slicelit" {
			return true
		}
		if v.Comment == "makeslice" {
			res := s.analyzeUsage(v)
			foundDyn := res&statusDyn != 0
			foundHard := res&statusHard != 0
			return foundHard || !foundDyn
		}
	case *ssa.MakeSlice:
		res := s.analyzeUsage(v)
		foundDyn := res&statusDyn != 0
		foundHard := res&statusHard != 0
		return foundHard || !foundDyn
	case *ssa.Call:
		if fn, ok := v.Call.Value.(*ssa.Function); ok {
			if res, ok := s.funcCache[fn]; ok {
				return res
			}
			if s.visitedFuncs[fn] {
				return false
			}
			s.visitedFuncs[fn] = true
			res := s.isFuncReturnsHardcoded(fn)
			s.funcCache[fn] = res
			delete(s.visitedFuncs, fn)
			return res
		}
	case *ssa.Parameter:
		return false
	}
	return false
}

func (s *analysisState) isFuncReturnsHardcoded(fn *ssa.Function) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if ret, ok := instr.(*ssa.Return); ok {
				if slices.ContainsFunc(ret.Results, s.isHardcoded) {
					return true
				}
			}
		}
	}
	return false
}

// analyzeUsage performs data-flow analysis to determine if a value is derived from
// a dynamic source (like crypto/rand) or if it's fixed/hardcoded.
func (s *analysisState) analyzeUsage(val ssa.Value) uint8 {
	if val == nil {
		return 0
	}
	if s.depth > MaxDepth {
		return statusDyn // assume dynamic avoid infinite recursion
	}
	if res, ok := s.usageCache[val]; ok {
		return res
	}
	s.usageCache[val] = statusVisiting

	s.depth++
	defer func() { s.depth-- }()

	var res uint8
	switch v := val.(type) {
	case *ssa.Const, *ssa.Global:
		res |= statusHard
	case *ssa.Alloc:
		if v.Comment == "slicelit" {
			res |= statusHard
		}
	case *ssa.Convert:
		res |= s.analyzeUsage(v.X)
	case *ssa.Slice:
		res |= s.analyzeUsage(v.X)
	case *ssa.UnOp:
		if v.Op == token.MUL {
			res |= s.analyzeUsage(v.X)
		}
	case *ssa.Call:
		if s.isHardcoded(v) {
			res |= statusHard
		}
	case *ssa.Parameter:
		if s.isHardcoded(v) {
			res |= statusHard
		}
	}

	if refs := val.Referrers(); refs != nil {
		for _, ref := range *refs {
			res |= s.analyzeReferrer(ref, val)
			if (res&statusDyn != 0) && (res&statusHard != 0) {
				finalRes := res & (^uint8(statusVisiting))
				s.usageCache[val] = finalRes
				return finalRes
			}
		}
	}

	if sl, ok := val.(*ssa.Slice); ok && (res&statusDyn == 0) {
		if sourceRefs := sl.X.Referrers(); sourceRefs != nil {
			for _, sr := range *sourceRefs {
				if other, ok := sr.(*ssa.Slice); ok && other != sl {
					if IsSubSlice(sl, other) {
						otherRes := s.analyzeUsage(other)
						if (otherRes&(^uint8(statusVisiting)))&statusDyn != 0 {
							res |= statusDyn
							break
						}
					}
				}
			}
		}
	}

	// Store final result (removing visiting bit)
	finalRes := res & (^uint8(statusVisiting))
	s.usageCache[val] = finalRes
	return finalRes
}

func (s *analysisState) analyzeReferrer(ref ssa.Instruction, val ssa.Value) uint8 {
	var res uint8
	switch r := ref.(type) {
	case *ssa.Call:
		isDynamic := false
		isCipher := false
		callValue := r.Call.Value

		// 1. Determine fast path status (Dynamic/Cipher)
		if fn, ok := callValue.(*ssa.Function); ok && fn.Pkg != nil && fn.Pkg.Pkg != nil {
			path := fn.Pkg.Pkg.Path()
			funcName := path + "." + fn.Name()
			if dynamicFuncs[funcName] {
				isDynamic = true
			} else {
				for _, prefix := range cipherPkgPrefixes {
					if strings.HasPrefix(path, prefix) {
						isCipher = true
						break
					}
				}
			}
		} else if r.Call.IsInvoke() && r.Call.Method != nil && r.Call.Method.Pkg() != nil {
			// Interface method invocation
			path := r.Call.Method.Pkg().Path()
			if dynamicPkgs[path] {
				isDynamic = true
			} else {
				for _, prefix := range cipherPkgPrefixes {
					if strings.HasPrefix(path, prefix) {
						isCipher = true
						break
					}
				}
			}
		} else {
			// Fallback string matching
			callStr := callValue.String()
			for k := range dynamicFuncs {
				if strings.Contains(callStr, k) {
					isDynamic = true
					break
				}
			}
			if !isDynamic {
				for _, prefix := range cipherPkgPrefixes {
					if strings.Contains(callStr, prefix) {
						isCipher = true
						break
					}
				}
			}
		}

		if isDynamic {
			return res | statusDyn
		}
		if isCipher {
			return res
		}

		// 2. Generic Function Resolution and Recursive Analysis
		clear(s.funcResolutionMap)
		var funcs []*ssa.Function
		s.resolveFuncs(callValue, &funcs)
		if len(funcs) == 0 {
			// If we couldn't resolve any functions (unknown library or dynamic call),
			// assume it might be dynamic/safe to avoid false positives.
			return statusDyn
		}
		for _, fn := range funcs {
			for i, arg := range r.Call.Args {
				if arg == val && i < len(fn.Params) {
					res |= s.analyzeUsage(fn.Params[i])
				}
			}
		}
		return res

	case *ssa.Slice:
		if refs := r.Referrers(); refs != nil {
			for _, ref := range *refs {
				res |= s.analyzeReferrer(ref, r)
			}
		}
		if !IsFullSlice(r, s.getBufferLen(r.X)) {
			res &= ^uint8(statusDyn)
		}
	case *ssa.IndexAddr, *ssa.Index, *ssa.Lookup:
		if vVal, ok := r.(ssa.Value); ok {
			rRes := s.analyzeUsage(vVal)
			res |= (rRes & statusHard)
		}
	case *ssa.UnOp:
		if r.Op == token.MUL {
			res |= s.analyzeUsage(r)
		}
	case *ssa.Convert:
		res |= s.analyzeUsage(r)
	case *ssa.Store:
		if r.Addr == val {
			valRes := s.analyzeUsage(r.Val)
			res |= (valRes & statusHard)
			res |= (valRes & statusDyn)
		}
	}
	return res
}

func (s *analysisState) resolveFuncs(val ssa.Value, funcs *[]*ssa.Function) {
	if val == nil || s.depth > MaxDepth {
		return
	}
	if s.funcResolutionMap[val] {
		return
	}
	s.funcResolutionMap[val] = true

	s.depth++
	defer func() { s.depth-- }()

	switch v := val.(type) {
	case *ssa.Function:
		*funcs = append(*funcs, v)
	case *ssa.MakeClosure:
		*funcs = append(*funcs, v.Fn.(*ssa.Function))
	case *ssa.Phi:
		for _, edge := range v.Edges {
			s.resolveFuncs(edge, funcs)
		}
	}
}

func (s *analysisState) getBufferLen(val ssa.Value) int64 {
	if res, ok := s.bufferLenCache[val]; ok {
		return res
	}
	length := GetBufferLen(val)
	s.bufferLenCache[val] = length
	return length
}

// allTaintedEventsCovered checks if all "tainting events" (Alloc, Store of hardcoded data)
// related to 'val' are effectively overwritten/covered by dynamic reads (e.g. crypto/rand.Read)
// before 'usage'. It handles partial overwrites by tracking byte ranges and execution order.
func (s *analysisState) allTaintedEventsCovered(val ssa.Value, usage ssa.Instruction) bool {
	// 1. Collection Phase: Gathering all Safe (Reads) and Unsafe (Allocs/Stores) actions.
	var actions []RangeAction

	v := val
	for {
		s.collectTaintedEvents(v, usage, &actions)
		s.collectCoveredRanges(v, usage, &actions)

		if unop, ok := v.(*ssa.UnOp); ok && unop.Op == token.MUL {
			v = unop.X
		} else if sl, ok := v.(*ssa.Slice); ok {
			v = sl.X
		} else if conv, ok := v.(*ssa.Convert); ok {
			v = conv.X
		} else if idx, ok := v.(*ssa.IndexAddr); ok {
			v = idx.X
		} else if alloc, ok := v.(*ssa.Alloc); ok {
			// Try to follow a local variable back to its source
			found := false
			if refs := alloc.Referrers(); refs != nil {
				for _, ref := range *refs {
					if st, ok := ref.(*ssa.Store); ok && st.Addr == alloc {
						v = st.Val
						found = true
						break
					}
				}
			}
			if !found {
				break
			}
		} else {
			break
		}
	}

	// 2. Identify and track the root allocation as the initial Unsafe Action.
	var bufLen int64
	if alloc, ok := v.(*ssa.Alloc); ok {
		bufLen = s.getBufferLen(alloc)
		if alloc.Comment == "slicelit" || alloc.Comment == "makeslice" {
			actions = append(actions, RangeAction{
				Instr:  alloc,
				Range:  ByteRange{0, bufLen},
				IsSafe: false,
			})
		}
	} else if mk, ok := v.(*ssa.MakeSlice); ok {
		if l, ok := GetConstantInt64(mk.Len); ok && l > 0 {
			bufLen = l
			actions = append(actions, RangeAction{
				Instr:  mk,
				Range:  ByteRange{0, bufLen},
				IsSafe: false,
			})
		}
	} else if conv, ok := val.(*ssa.Convert); ok {
		if c, ok := conv.X.(*ssa.Const); ok && c.Value.Kind() == constant.String {
			bufLen = int64(len(constant.StringVal(c.Value)))
		}
	} else {
		if bufRange, ok := s.resolveAbsoluteRange(v); ok {
			bufLen = bufRange.High
		}
	}

	if bufLen <= 0 {
		return false
	}

	// 3. Sequence Phase: Sort actions based on their execution order in the SSA graph.
	slices.SortFunc(actions, func(a, b RangeAction) int {
		if s.analyzer.Precedes(a.Instr, b.Instr) {
			return -1
		}
		if a.Instr == b.Instr {
			return 0
		}
		return 1
	})

	// 4. Replay Phase: Simulate the buffer state sequentially.
	var safeRanges []ByteRange
	var scratchRanges []ByteRange
	for i := 0; i < len(actions); {
		if actions[i].IsSafe {
			// Collect and batch safe actions to minimize mergeRanges overhead
			j := i
			for j < len(actions) && actions[j].IsSafe {
				safeRanges = append(safeRanges, actions[j].Range)
				j++
			}
			mergedSafe := mergeRanges(safeRanges)
			safeRanges = mergedSafe
			i = j
		} else {
			// Subtract range
			subtractRange(safeRanges, actions[i].Range, &scratchRanges)
			safeRanges, scratchRanges = scratchRanges, safeRanges
			i++
		}
	}

	// 5. Verification Phase: Check if the resulting safe ranges cover the target range.
	targetRange, ok := s.resolveAbsoluteRange(val)
	if !ok {
		return false
	}

	for _, r := range safeRanges {
		if r.Low <= targetRange.Low && r.High >= targetRange.High {
			return true
		}
	}
	return false
}

// collectTaintedEvents traverses the SSA referrers of 'val' to find hardcoded stores.
// It recursively follows slices and pointer aliases to find indirect taints.
func (s *analysisState) collectTaintedEvents(val ssa.Value, usage ssa.Instruction, actions *[]RangeAction) {
	refs := val.Referrers()
	if refs == nil {
		return
	}

	for _, ref := range *refs {
		isHard := s.analyzeReferrer(ref, val)&statusHard != 0
		if isHard {
			if s.analyzer.Precedes(ref, usage) {
				// Determine range of the Store
				if store, ok := ref.(*ssa.Store); ok && store.Addr == val {
					// Storing hardcoded data into this buffer
					if absRange, ok := s.resolveAbsoluteRange(store.Addr); ok {
						*actions = append(*actions, RangeAction{
							Instr:  ref,
							Range:  absRange,
							IsSafe: false,
						})
					}
				}
			}
		}

		// Follow stores into pointers/interfaces
		if store, ok := ref.(*ssa.Store); ok && store.Addr == val {
			s.collectTaintedEvents(store.Val, usage, actions)
		}

		// Trace into slices/indexers
		if v, ok := ref.(ssa.Value); ok {
			switch r := ref.(type) {
			case *ssa.Slice, *ssa.IndexAddr:
				s.collectTaintedEvents(v, usage, actions)
			case *ssa.UnOp:
				if r.Op == token.MUL {
					s.collectTaintedEvents(v, usage, actions)
				}
			}
		}
	}
}

// collectCoveredRanges traverses the SSA referrers to find dynamic read operations
// that safely overwrite portions of the buffer before it is used.
func (s *analysisState) collectCoveredRanges(val ssa.Value, usage ssa.Instruction, actions *[]RangeAction) {
	refs := val.Referrers()
	if refs == nil {
		return
	}

	for _, ref := range *refs {
		if s.isFullDynamicRead(ref, val) {
			if s.analyzer.Precedes(ref, usage) {
				if absRange, ok := s.resolveAbsoluteRange(val); ok {
					*actions = append(*actions, RangeAction{
						Instr:  ref,
						Range:  absRange,
						IsSafe: true,
					})
				}
			}
		}

		// Follow stores into pointers/interfaces
		if store, ok := ref.(*ssa.Store); ok && store.Addr == val {
			s.collectCoveredRanges(store.Val, usage, actions)
		}

		// Recurse into slices/indexers to find reads on sub-slices
		if v, ok := ref.(ssa.Value); ok {
			switch r := ref.(type) {
			case *ssa.Slice, *ssa.IndexAddr:
				s.collectCoveredRanges(v, usage, actions)
			case *ssa.UnOp:
				if r.Op == token.MUL {
					s.collectCoveredRanges(v, usage, actions)
				}
			}
		}
	}
}

// isFullDynamicRead checks if the given 'ref' instruction is a call to a known dynamic function
// (like io.ReadFull or crypto/rand.Read) and if 'val' is passed as an argument to it.
func (s *analysisState) isFullDynamicRead(ref ssa.Instruction, val ssa.Value) bool {
	call, ok := ref.(*ssa.Call)
	if !ok {
		return false
	}
	callValue := call.Call.Value

	// 1. Check immediate calls to known dynamic functions
	isDynamic := false
	if fn, ok := callValue.(*ssa.Function); ok && fn.Pkg != nil && fn.Pkg.Pkg != nil {
		if dynamicFuncs[fn.Pkg.Pkg.Path()+"."+fn.Name()] {
			isDynamic = true
		}
	} else if call.Call.IsInvoke() && call.Call.Method != nil && call.Call.Method.Pkg() != nil {
		if dynamicPkgs[call.Call.Method.Pkg().Path()] {
			isDynamic = true
		}
	}

	if isDynamic {
		// Verify if val is passed as an argument
		return slices.Contains(call.Call.Args, val)
	}

	// 2. Check calls to user-defined functions that eventually call dynamic reads.
	// We use analyzeUsage on the function parameters to determine this.
	// We only trust it as a safeguard if it is purely dynamic (not hardcoded).
	// If we cannot resolve the function, assume it is safe to avoid False Positives.
	clear(s.funcResolutionMap)
	var funcs []*ssa.Function
	s.resolveFuncs(callValue, &funcs)
	if len(funcs) == 0 {
		return true
	}
	for _, fn := range funcs {
		for i, arg := range call.Call.Args {
			if arg == val && i < len(fn.Params) {
				status := s.analyzeUsage(fn.Params[i])
				if (status&statusDyn != 0) && (status&statusHard == 0) {
					return true
				}
			}
		}
	}

	return false
}

// ByteRange represents a range [Low, High)
type ByteRange struct {
	Low  int64
	High int64
}

type RangeAction struct {
	Instr  ssa.Instruction
	Range  ByteRange
	IsSafe bool // true = Read (Dynamic), false = Write/Alloc (Hardcoded)
}

// mergeRanges takes a list of ByteRanges and merges overlapping or contiguous ranges.
// It modifies the input slice in-place to reduce allocations and returns a slice of disjoint ranges.
func mergeRanges(ranges []ByteRange) []ByteRange {
	if len(ranges) <= 1 {
		return ranges
	}
	slices.SortFunc(ranges, func(a, b ByteRange) int {
		return cmp.Compare(a.Low, b.Low)
	})

	// In-place merge
	// 'idx' points to the position of the 'current' merged range being built.
	idx := 0
	for _, r := range ranges[1:] {
		if r.Low <= ranges[idx].High {
			ranges[idx].High = max(ranges[idx].High, r.High)
		} else {
			idx++
			ranges[idx] = r
		}
	}
	return ranges[:idx+1]
}

// subtractRange removes 'taint' range from the list of 'safe' ranges, potentially
// splitting existing safe ranges into two separate fragments. The results are appended to 'dest'.
func subtractRange(safe []ByteRange, taint ByteRange, dest *[]ByteRange) {
	*dest = (*dest)[:0]
	for _, r := range safe {
		// No overlap
		if r.High <= taint.Low || r.Low >= taint.High {
			*dest = append(*dest, r)
			continue
		}

		if r.Low < taint.Low {
			*dest = append(*dest, ByteRange{r.Low, taint.Low})
		}
		if r.High > taint.High {
			*dest = append(*dest, ByteRange{taint.High, r.High})
		}
	}
}

// resolveAbsoluteRange determines the absolute byte range of 'val' relative to its
// underlying root allocation by recursively resolving slice offsets and indices.
func (s *analysisState) resolveAbsoluteRange(val ssa.Value) (ByteRange, bool) {
	if r, ok := s.rangeCache[val]; ok {
		return r, true
	}

	if s.depth > MaxDepth {
		return ByteRange{}, false
	}
	s.depth++
	defer func() { s.depth-- }()

	res, ok := s.recursiveRange(val)
	if ok {
		s.rangeCache[val] = res
	}
	return res, ok
}

// recursiveRange is a helper for resolveAbsoluteRange that traverses up the SSA value chain
// (handling Slice, IndexAddr, Convert, etc.) to compute the range.
func (s *analysisState) recursiveRange(val ssa.Value) (ByteRange, bool) {
	switch v := val.(type) {
	case *ssa.Alloc:
		l := s.getBufferLen(v)
		if l <= 0 {
			// If it is a local variable slot, try to find what was stored in it
			if refs := v.Referrers(); refs != nil {
				for _, ref := range *refs {
					if st, ok := ref.(*ssa.Store); ok && st.Addr == v {
						return s.recursiveRange(st.Val)
					}
				}
			}
			return ByteRange{}, false
		}
		return ByteRange{0, l}, true
	case *ssa.MakeSlice:
		if l, ok := GetConstantInt64(v.Len); ok && l > 0 {
			return ByteRange{0, l}, true
		}
		return ByteRange{}, false
	case *ssa.Convert:
		if c, ok := v.X.(*ssa.Const); ok && c.Value.Kind() == constant.String {
			l := int64(len(constant.StringVal(c.Value)))
			if l > 0 {
				return ByteRange{0, l}, true
			}
		}
		return ByteRange{}, false
	case *ssa.Slice:
		parentRange, ok := s.recursiveRange(v.X)
		if !ok {
			return ByteRange{}, false
		}

		var low int64
		if v.Low != nil {
			l, ok := GetConstantInt64(v.Low)
			if !ok {
				res := s.analyzer.ResolveRange(v.Low, v.Block())
				if res.isRangeCheck && res.maxValueSet {
					l = toInt64(res.maxValue)
				} else {
					return ByteRange{}, false
				}
				s.analyzer.releaseResult(res)
			}
			low = l
		}

		var high int64
		if v.High == nil {
			high = parentRange.High
		} else {
			h, ok := GetConstantInt64(v.High)
			if !ok {
				res := s.analyzer.ResolveRange(v.High, v.Block())
				if res.isRangeCheck && res.maxValueSet {
					h = toInt64(res.maxValue)
				} else {
					return ByteRange{}, false
				}
			}
			high = parentRange.Low + h
		}

		newLow := parentRange.Low + low
		newHigh := min(high, parentRange.High)
		if newLow >= newHigh {
			return ByteRange{newLow, newLow}, true // Handle empty slices consistently
		}
		return ByteRange{newLow, newHigh}, true
	case *ssa.IndexAddr:
		parentRange, ok := s.recursiveRange(v.X)
		if !ok {
			return ByteRange{}, false
		}
		if c, ok := GetConstantInt64(v.Index); ok {
			start := parentRange.Low + c
			return ByteRange{start, start + 1}, true
		}
		// Check for explicit range checks.
		res := s.analyzer.ResolveRange(v.Index, v.Block())
		if res.isRangeCheck && res.minValueSet && res.maxValueSet {
			minVal := toInt64(res.minValue)
			maxVal := toInt64(res.maxValue)
			if minVal > maxVal {
				// Contradictory range (unreachable code). Conservatively report as full taint to satisfy tests expecting issues in dead code.
				return ByteRange{parentRange.Low, parentRange.High}, true
			}
			start := parentRange.Low + minVal
			end := parentRange.Low + maxVal + 1
			return ByteRange{start, end}, true
		}
		return ByteRange{}, false
	case *ssa.UnOp:
		if v.Op == token.MUL {
			return s.recursiveRange(v.X)
		}
	}
	return ByteRange{}, false
}
