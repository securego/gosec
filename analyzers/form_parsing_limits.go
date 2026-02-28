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
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

const msgUnboundedFormParsing = "Parsing form data without limiting request body size can allow memory exhaustion (use http.MaxBytesReader)"

type dependencyKey struct {
	value  ssa.Value
	target ssa.Value
}

type dependencyChecker struct {
	memo     map[dependencyKey]bool
	visiting map[dependencyKey]struct{}
}

func newDependencyChecker() *dependencyChecker {
	return &dependencyChecker{
		memo:     make(map[dependencyKey]bool),
		visiting: make(map[dependencyKey]struct{}),
	}
}

func (c *dependencyChecker) dependsOn(value ssa.Value, target ssa.Value) bool {
	return c.dependsOnDepth(value, target, 0)
}

func (c *dependencyChecker) dependsOnDepth(value ssa.Value, target ssa.Value, depth int) bool {
	if value == nil || target == nil || depth > MaxDepth {
		return false
	}
	if value == target {
		return true
	}

	key := dependencyKey{value: value, target: target}
	if result, ok := c.memo[key]; ok {
		return result
	}
	if _, ok := c.visiting[key]; ok {
		return false
	}

	c.visiting[key] = struct{}{}
	result := false

	switch v := value.(type) {
	case *ssa.ChangeType:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.MakeInterface:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.TypeAssert:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.UnOp:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.FieldAddr:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.Field:
		result = c.dependsOnDepth(v.X, target, depth+1)
	case *ssa.IndexAddr:
		result = c.dependsOnDepth(v.X, target, depth+1) || c.dependsOnDepth(v.Index, target, depth+1)
	case *ssa.Index:
		result = c.dependsOnDepth(v.X, target, depth+1) || c.dependsOnDepth(v.Index, target, depth+1)
	case *ssa.Slice:
		if c.dependsOnDepth(v.X, target, depth+1) {
			result = true
			break
		}
		if v.Low != nil && c.dependsOnDepth(v.Low, target, depth+1) {
			result = true
			break
		}
		if v.High != nil && c.dependsOnDepth(v.High, target, depth+1) {
			result = true
			break
		}
		result = v.Max != nil && c.dependsOnDepth(v.Max, target, depth+1)
	case *ssa.Extract:
		result = c.dependsOnDepth(v.Tuple, target, depth+1)
	case *ssa.Phi:
		for _, edge := range v.Edges {
			if c.dependsOnDepth(edge, target, depth+1) {
				result = true
				break
			}
		}
	case *ssa.Call:
		if v.Call.Value != nil && c.dependsOnDepth(v.Call.Value, target, depth+1) {
			result = true
			break
		}
		for _, arg := range v.Call.Args {
			if c.dependsOnDepth(arg, target, depth+1) {
				result = true
				break
			}
		}
	}

	delete(c.visiting, key)
	c.memo[key] = result

	return result
}

func newFormParsingLimitAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runFormParsingLimitAnalysis,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runFormParsingLimitAnalysis(pass *analysis.Pass) (any, error) {
	ssaResult, err := ssautil.GetSSAResult(pass)
	if err != nil {
		return nil, err
	}

	checker := newDependencyChecker()
	issuesByPos := make(map[token.Pos]*issue.Issue)
	handlerProtection := computeFormParsingHandlerProtection(ssaResult.SSA.SrcFuncs, checker)

	for _, fn := range collectAnalyzerFunctions(ssaResult.SSA.SrcFuncs) {
		requestParam, writerParam := findHandlerRequestAndWriterParams(fn)
		if requestParam == nil || writerParam == nil {
			continue
		}

		hasRequestBodyLimit := handlerProtection[fn]
		if hasRequestBodyLimit {
			continue
		}

		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				callInstr, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if !isRiskyFormParsingCall(callInstr, requestParam, checker) {
					continue
				}
				addRedirectIssue(issuesByPos, pass, instr.Pos(), msgUnboundedFormParsing, issue.Medium, issue.High)
			}
		}
	}

	if len(issuesByPos) == 0 {
		return nil, nil
	}

	issues := make([]*issue.Issue, 0, len(issuesByPos))
	for _, i := range issuesByPos {
		issues = append(issues, i)
	}

	return issues, nil
}

func computeFormParsingHandlerProtection(srcFuncs []*ssa.Function, checker *dependencyChecker) map[*ssa.Function]bool {
	protection := make(map[*ssa.Function]bool)
	allFuncs := collectAnalyzerFunctions(srcFuncs)
	for _, fn := range allFuncs {
		requestParam, writerParam := findHandlerRequestAndWriterParams(fn)
		if requestParam == nil || writerParam == nil {
			continue
		}
		if functionHasRequestBodyLimit(fn, requestParam, writerParam, checker) {
			protection[fn] = true
			continue
		}
		if isProtectedByWrapperCall(fn, allFuncs, checker) {
			protection[fn] = true
		}
	}

	return protection
}

func isProtectedByWrapperCall(handler *ssa.Function, allFuncs []*ssa.Function, checker *dependencyChecker) bool {
	for _, fn := range allFuncs {
		if fn == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				callInstr, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				common := callInstr.Common()
				if common == nil {
					continue
				}
				wrapper := common.StaticCallee()
				if wrapper == nil {
					continue
				}

				for argIndex, arg := range common.Args {
					if !checker.dependsOn(arg, handler) {
						continue
					}
					if wrapperProtectsParamHandler(wrapper, argIndex, checker) {
						return true
					}
				}
			}
		}
	}

	return false
}

func wrapperProtectsParamHandler(wrapper *ssa.Function, paramIndex int, checker *dependencyChecker) bool {
	if wrapper == nil || paramIndex < 0 || paramIndex >= len(wrapper.Params) {
		return false
	}
	handlerParam := wrapper.Params[paramIndex]

	if wrapperDelegatesWithRequestLimit(wrapper, handlerParam, checker) {
		return true
	}

	for _, block := range wrapper.Blocks {
		for _, instr := range block.Instrs {
			makeClosure, ok := instr.(*ssa.MakeClosure)
			if !ok {
				continue
			}
			closureFn, ok := makeClosure.Fn.(*ssa.Function)
			if !ok || closureFn == nil {
				continue
			}

			requestParam, writerParam := findHandlerRequestAndWriterParams(closureFn)
			if requestParam == nil || writerParam == nil {
				continue
			}
			if !functionHasRequestBodyLimit(closureFn, requestParam, writerParam, checker) {
				continue
			}

			for bindingIndex, binding := range makeClosure.Bindings {
				if !bindingDependsOnValue(binding, handlerParam, checker) {
					continue
				}
				if closureDelegatesWithRequestLimit(closureFn, bindingIndex, requestParam, writerParam, checker) {
					return true
				}
			}
		}
	}

	return false
}

func bindingDependsOnValue(binding ssa.Value, target ssa.Value, checker *dependencyChecker) bool {
	if checker.dependsOn(binding, target) {
		return true
	}

	alloc, ok := binding.(*ssa.Alloc)
	if !ok {
		return false
	}

	for _, ref := range safeReferrers(alloc) {
		store, ok := ref.(*ssa.Store)
		if !ok {
			continue
		}
		if store.Addr != alloc {
			continue
		}
		if checker.dependsOn(store.Val, target) {
			return true
		}
	}

	return false
}

func wrapperDelegatesWithRequestLimit(wrapper *ssa.Function, handlerValue ssa.Value, checker *dependencyChecker) bool {
	requestParam, writerParam := findHandlerRequestAndWriterParams(wrapper)
	if requestParam == nil || writerParam == nil {
		return false
	}
	if !functionHasRequestBodyLimit(wrapper, requestParam, writerParam, checker) {
		return false
	}
	return hasServeHTTPDelegation(wrapper, handlerValue, writerParam, requestParam, checker)
}

func closureDelegatesWithRequestLimit(closure *ssa.Function, freeVarIndex int, requestParam *ssa.Parameter, writerParam *ssa.Parameter, checker *dependencyChecker) bool {
	if freeVarIndex < 0 || freeVarIndex >= len(closure.FreeVars) {
		return false
	}
	handlerValue := closure.FreeVars[freeVarIndex]
	return hasServeHTTPDelegation(closure, handlerValue, writerParam, requestParam, checker)
}

func hasServeHTTPDelegation(fn *ssa.Function, handlerValue ssa.Value, writerValue ssa.Value, requestValue ssa.Value, checker *dependencyChecker) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			common := call.Common()
			if common == nil {
				continue
			}

			var (
				receiver ssa.Value
				writer   ssa.Value
				request  ssa.Value
			)

			if method := common.Method; method != nil && method.Name() == "ServeHTTP" {
				if len(common.Args) < 2 {
					continue
				}
				receiver = common.Value
				writer = common.Args[0]
				request = common.Args[1]
			} else {
				callee := common.StaticCallee()
				if callee == nil || callee.Name() != "ServeHTTP" || callee.Signature == nil || callee.Signature.Recv() == nil {
					continue
				}
				if len(common.Args) < 3 {
					continue
				}
				receiver = common.Args[0]
				writer = common.Args[1]
				request = common.Args[2]
			}

			if !checker.dependsOn(receiver, handlerValue) {
				continue
			}
			if !checker.dependsOn(writer, writerValue) {
				continue
			}
			if !checker.dependsOn(request, requestValue) {
				continue
			}
			return true
		}
	}

	return false
}

func findHandlerRequestAndWriterParams(fn *ssa.Function) (*ssa.Parameter, *ssa.Parameter) {
	if fn == nil {
		return nil, nil
	}

	var requestParam *ssa.Parameter
	var writerParam *ssa.Parameter

	for _, param := range fn.Params {
		if param == nil {
			continue
		}
		if requestParam == nil && isHTTPRequestPointerType(param.Type()) {
			requestParam = param
			continue
		}
		if writerParam == nil && isHTTPResponseWriterType(param.Type()) {
			writerParam = param
		}
	}

	return requestParam, writerParam
}

func isHTTPResponseWriterType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}

	obj := named.Obj()
	if obj == nil || obj.Name() != "ResponseWriter" {
		return false
	}

	pkg := obj.Pkg()
	return pkg != nil && pkg.Path() == "net/http"
}

func functionHasRequestBodyLimit(fn *ssa.Function, requestParam *ssa.Parameter, writerParam *ssa.Parameter, checker *dependencyChecker) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}
			if isRequestBodyStoreFromMaxBytesReader(store, requestParam, writerParam, checker) {
				return true
			}
		}
	}
	return false
}

func isRequestBodyStoreFromMaxBytesReader(store *ssa.Store, requestParam *ssa.Parameter, writerParam *ssa.Parameter, checker *dependencyChecker) bool {
	fieldAddr, ok := store.Addr.(*ssa.FieldAddr)
	if !ok {
		return false
	}

	if !checker.dependsOn(fieldAddr.X, requestParam) {
		return false
	}

	if !isMaxBytesReaderValue(store.Val, requestParam, writerParam, checker, 0) {
		return false
	}

	return true
}

func isMaxBytesReaderValue(v ssa.Value, requestParam *ssa.Parameter, writerParam *ssa.Parameter, checker *dependencyChecker, depth int) bool {
	if v == nil || depth > MaxDepth {
		return false
	}

	switch value := v.(type) {
	case *ssa.Call:
		callee := value.Call.StaticCallee()
		if callee == nil || callee.Name() != "MaxBytesReader" {
			return false
		}
		if callee.Pkg == nil || callee.Pkg.Pkg == nil || callee.Pkg.Pkg.Path() != "net/http" {
			return false
		}
		if len(value.Call.Args) < 3 {
			return false
		}
		if !checker.dependsOn(value.Call.Args[0], writerParam) {
			return false
		}
		return checker.dependsOn(value.Call.Args[1], requestParam)
	case *ssa.ChangeType:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, checker, depth+1)
	case *ssa.MakeInterface:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, checker, depth+1)
	case *ssa.TypeAssert:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, checker, depth+1)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			if isMaxBytesReaderValue(edge, requestParam, writerParam, checker, depth+1) {
				return true
			}
		}
	}

	return false
}

func isRiskyFormParsingCall(callInstr ssa.CallInstruction, requestParam *ssa.Parameter, checker *dependencyChecker) bool {
	common := callInstr.Common()
	if common == nil {
		return false
	}

	callee := common.StaticCallee()
	if callee == nil {
		return false
	}

	if callee.Signature == nil || callee.Signature.Recv() == nil {
		return false
	}

	if !isHTTPRequestPointerType(callee.Signature.Recv().Type()) {
		return false
	}

	name := callee.Name()
	if name != "ParseForm" && name != "ParseMultipartForm" && name != "FormValue" && name != "PostFormValue" {
		return false
	}

	if len(common.Args) == 0 {
		return false
	}

	return checker.dependsOn(common.Args[0], requestParam)
}
