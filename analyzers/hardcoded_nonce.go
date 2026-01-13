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
	depth             int
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
					funcs := s.resolveFuncs(c.Call.Value)
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
	foundHardWrite := res&statusHardWrite != 0

	if foundDyn {
		if !foundHardWrite {
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
			foundDyn := res&statusDyn != 0
			foundHard := res&statusHard != 0 || res&statusHardWrite != 0
			if foundHard {
				issueDescription += " by passing a buffer from make modified with hardcoded values"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			} else if !foundDyn {
				issueDescription += " by passing a zeroed buffer from make"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			}
		}
	case *ssa.MakeSlice:
		res := s.analyzeUsage(v)
		foundDyn := res&statusDyn != 0
		foundHard := res&statusHard != 0 || res&statusHardWrite != 0
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
			foundHard := res&statusHard != 0 || res&statusHardWrite != 0
			return foundHard || !foundDyn
		}
	case *ssa.MakeSlice:
		res := s.analyzeUsage(v)
		foundDyn := res&statusDyn != 0
		foundHard := res&statusHard != 0 || res&statusHardWrite != 0
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

const (
	statusVisiting  = 1 << 0
	statusHard      = 1 << 1
	statusDyn       = 1 << 2
	statusHardWrite = 1 << 3
)

// analyzeUsage performs data-flow analysis to determine if a value is derived from
// a dynamic source (like crypto/rand) or if it's fixed/hardcoded.
func (s *analysisState) analyzeUsage(val ssa.Value) uint8 {
	if val == nil || s.depth > MaxDepth {
		return 0
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
		if !s.isFullSlice(v) {
			// If not full slice, unset Dyn bit from result as it might not be covered
			res &= ^uint8(statusDyn)
		}
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
			if (res&statusDyn != 0) && (res&statusHard != 0) && (res&statusHardWrite != 0) {
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
					if isSubSlice(sl, other) {
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
		funcs := s.resolveFuncs(callValue)
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
		if !s.isFullSlice(r) {
			res &= ^uint8(statusDyn)
		}
	case *ssa.IndexAddr, *ssa.Index, *ssa.Lookup:
		if vVal, ok := r.(ssa.Value); ok {
			rRes := s.analyzeUsage(vVal)
			res |= (rRes & (statusHard | statusHardWrite))
		}
	case *ssa.UnOp:
		if r.Op == token.MUL {
			res |= s.analyzeUsage(r)
		}
	case *ssa.Convert:
		res |= s.analyzeUsage(r)
	case *ssa.Store:
		if r.Addr == val {
			if s.isHardcoded(r.Val) {
				res |= statusHard | statusHardWrite
				return res
			}
		}
	}
	return res
}

func (s *analysisState) resolveFuncs(val ssa.Value) []*ssa.Function {
	if val == nil || s.depth > MaxDepth {
		return nil
	}
	if s.funcResolutionMap[val] {
		return nil
	}
	s.funcResolutionMap[val] = true

	s.depth++
	defer func() { s.depth-- }()

	switch v := val.(type) {
	case *ssa.Function:
		return []*ssa.Function{v}
	case *ssa.MakeClosure:
		return []*ssa.Function{v.Fn.(*ssa.Function)}
	case *ssa.Phi:
		var funcs []*ssa.Function
		for _, edge := range v.Edges {
			if f := s.resolveFuncs(edge); f != nil {
				funcs = append(funcs, f...)
			}
		}
		return funcs
	}
	return nil
}

func (s *analysisState) isFullSlice(sl *ssa.Slice) bool {
	l, h := getSliceRange(sl)
	if l != 0 {
		return false
	}
	if h < 0 {
		return true
	}
	return h == s.getBufferLen(sl.X)
}

func (s *analysisState) getBufferLen(val ssa.Value) int64 {
	if res, ok := s.bufferLenCache[val]; ok {
		return res
	}
	length := GetBufferLen(val)
	s.bufferLenCache[val] = length
	return length
}

func isSubSlice(sub, super *ssa.Slice) bool {
	l1, h1 := getSliceRange(sub)
	l2, h2 := getSliceRange(super)
	if l1 < 0 || l2 < 0 {
		return false
	}
	if l2 > l1 {
		return false
	}
	if h2 < 0 {
		return true
	}
	if h1 < 0 {
		return false
	}
	return h1 <= h2
}

func getSliceRange(s *ssa.Slice) (int64, int64) {
	l, h, _ := GetSliceBounds(s)
	return int64(l), int64(h)
}
