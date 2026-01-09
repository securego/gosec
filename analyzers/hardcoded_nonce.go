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
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

const defaultIssueDescription = "Use of hardcoded IV/nonce for encryption"

func newHardCodedNonce(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runHardCodedNonce,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runHardCodedNonce(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, err
	}

	state := newAnalysisState(pass, ssaResult.SSA.SrcFuncs)

	tracked := map[string][]int{
		"(crypto/cipher.AEAD).Seal":     {4, 1},
		"crypto/cipher.NewCBCEncrypter": {2, 1},
		"crypto/cipher.NewCFBEncrypter": {2, 1},
		"crypto/cipher.NewCTR":          {2, 1},
		"crypto/cipher.NewOFB":          {2, 1},
	}

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

type usageResult struct {
	dyn  bool
	hard bool
}

type analysisState struct {
	pass           *analysis.Pass
	ssaFuncs       []*ssa.Function
	usageCache     map[ssa.Value]*usageResult
	funcCache      map[*ssa.Function]bool
	visitedFuncs   map[*ssa.Function]bool
	callerMap      map[string][]*ssa.Call
	bufferLenCache map[ssa.Value]int64
	depth          int
}

type ssaValueAndInstr struct {
	val   ssa.Value
	instr ssa.Instruction
}

func newAnalysisState(pass *analysis.Pass, funcs []*ssa.Function) *analysisState {
	s := &analysisState{
		pass:           pass,
		ssaFuncs:       funcs,
		usageCache:     make(map[ssa.Value]*usageResult),
		funcCache:      make(map[*ssa.Function]bool),
		visitedFuncs:   make(map[*ssa.Function]bool),
		callerMap:      make(map[string][]*ssa.Call),
		bufferLenCache: make(map[ssa.Value]int64),
	}
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
					s.callerMap[name] = append(s.callerMap[name], c)
				}
			}
		}
	}
	return s
}

func (s *analysisState) getInitialArgs(tracked map[string][]int) []ssaValueAndInstr {
	var result []ssaValueAndInstr
	for name, info := range tracked {
		if calls, ok := s.callerMap[name]; ok {
			for _, c := range calls {
				if len(c.Call.Args) == info[0] {
					result = append(result, ssaValueAndInstr{
						val:   c.Call.Args[info[1]],
						instr: c,
					})
				}
			}
		}
	}
	return result
}

func (s *analysisState) raiseIssue(val ssa.Value, issueDescription string,
	visitedParams map[ssa.Value]bool, fromInstr ssa.Instruction,
) ([]*issue.Issue, error) {
	if visitedParams[val] {
		return nil, nil
	}
	visitedParams[val] = true

	foundDyn, foundHard := s.analyzeUsage(val)
	if foundDyn && !foundHard {
		return nil, nil
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
			foundDyn, foundHard := s.analyzeUsage(v)
			if foundHard {
				issueDescription += " by passing a buffer from make modified with hardcoded values"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			} else if !foundDyn {
				issueDescription += " by passing a zeroed buffer from make"
				allIssues = append(allIssues, newIssue(s.pass.Analyzer.Name, issueDescription, s.pass.Fset, fromInstr.Pos(), issue.High, issue.High))
			}
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
			dyn, hard := s.analyzeUsage(v)
			return hard || !dyn
		}
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
				for _, res := range ret.Results {
					if s.isHardcoded(res) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *analysisState) analyzeUsage(val ssa.Value) (bool, bool) {
	if val == nil || s.depth > MaxDepth {
		return false, false
	}
	if res, ok := s.usageCache[val]; ok {
		if res == nil { // currently visiting
			return false, false
		}
		return res.dyn, res.hard
	}
	s.usageCache[val] = nil // mark as visiting
	s.depth++
	defer func() { s.depth-- }()

	dyn := false
	hard := false

	switch v := val.(type) {
	case *ssa.Const, *ssa.Global:
		hard = true
	case *ssa.Alloc:
		if v.Comment == "slicelit" {
			hard = true
		}
	case *ssa.Convert:
		d, h := s.analyzeUsage(v.X)
		dyn, hard = dyn || d, hard || h
	case *ssa.Slice:
		d, h := s.analyzeUsage(v.X)
		if s.isFullSlice(v) {
			dyn = dyn || d
		}
		hard = hard || h
	case *ssa.UnOp:
		if v.Op == token.MUL {
			d, h := s.analyzeUsage(v.X)
			dyn, hard = dyn || d, hard || h
		}
	case *ssa.Call:
		if s.isHardcoded(v) {
			hard = true
		}
	case *ssa.Parameter:
		if s.isHardcoded(v) {
			hard = true
		}
	}

	if refs := val.Referrers(); refs != nil {
		for _, ref := range *refs {
			switch r := ref.(type) {
			case *ssa.Call:
				callStr := r.Call.Value.String()
				if strings.Contains(callStr, "crypto/rand") || strings.Contains(callStr, "io.ReadFull") {
					dyn = true
					continue
				}
				if strings.Contains(callStr, "crypto/cipher") || strings.Contains(callStr, "crypto/aes") {
					continue
				}
				if fn, ok := r.Call.Value.(*ssa.Function); ok && fn.Pkg != nil {
					for i, arg := range r.Call.Args {
						if arg == val {
							if i < len(fn.Params) {
								d, h := s.analyzeUsage(fn.Params[i])
								dyn, hard = dyn || d, hard || h
							}
						}
					}
					continue
				}
				dyn = true
			case *ssa.Slice:
				d, h := s.analyzeUsage(r)
				if s.isFullSlice(r) {
					dyn = dyn || d
				}
				hard = hard || h
			case *ssa.IndexAddr, *ssa.Index, *ssa.Lookup:
				if vVal, ok := r.(ssa.Value); ok {
					_, h := s.analyzeUsage(vVal)
					hard = hard || h
				}
			case *ssa.UnOp:
				if r.Op == token.MUL {
					d, h := s.analyzeUsage(r)
					dyn, hard = dyn || d, hard || h
				}
			case *ssa.Convert:
				d, h := s.analyzeUsage(r)
				dyn, hard = dyn || d, hard || h
			case *ssa.Store:
				if r.Addr == val {
					if s.isHardcoded(r.Val) {
						hard = true
					} else {
						dyn = true
					}
				}
			}
		}
	}

	if sl, ok := val.(*ssa.Slice); ok && !dyn {
		if sourceRefs := sl.X.Referrers(); sourceRefs != nil {
			for _, sr := range *sourceRefs {
				if other, ok := sr.(*ssa.Slice); ok && other != sl {
					if isSubSlice(sl, other) {
						d, _ := s.analyzeUsage(other)
						if d {
							dyn = true
							break
						}
					}
				}
			}
		}
	}

	res := &usageResult{dyn, hard}
	s.usageCache[val] = res
	return dyn, hard
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
	current := val
	for {
		t := current.Type()
		if ptr, ok := t.Underlying().(*types.Pointer); ok {
			t = ptr.Elem().Underlying()
		}
		if arr, ok := t.(*types.Array); ok {
			s.bufferLenCache[val] = arr.Len()
			return arr.Len()
		}
		if sl, ok := current.(*ssa.Slice); ok {
			current = sl.X
			continue
		}
		break
	}
	s.bufferLenCache[val] = -1
	return -1
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
	low := int64(0)
	if s.Low != nil {
		if c, ok := s.Low.(*ssa.Const); ok {
			if v, ok := constant.Int64Val(c.Value); ok {
				low = v
			} else {
				return -1, -1
			}
		} else {
			return -1, -1
		}
	}
	high := int64(-1)
	if s.High != nil {
		if c, ok := s.High.(*ssa.Const); ok {
			if v, ok := constant.Int64Val(c.Value); ok {
				high = v
			} else {
				return -1, -1
			}
		} else {
			return -1, -1
		}
	}
	return low, high
}
