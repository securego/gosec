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

	issuesByPos := make(map[token.Pos]*issue.Issue)

	for _, fn := range collectAnalyzerFunctions(ssaResult.SSA.SrcFuncs) {
		requestParam, writerParam := findHandlerRequestAndWriterParams(fn)
		if requestParam == nil || writerParam == nil {
			continue
		}

		hasRequestBodyLimit := functionHasRequestBodyLimit(fn, requestParam, writerParam)
		if hasRequestBodyLimit {
			continue
		}

		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				callInstr, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if !isRiskyFormParsingCall(callInstr, requestParam) {
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

func functionHasRequestBodyLimit(fn *ssa.Function, requestParam *ssa.Parameter, writerParam *ssa.Parameter) bool {
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}
			if isRequestBodyStoreFromMaxBytesReader(store, requestParam, writerParam) {
				return true
			}
		}
	}
	return false
}

func isRequestBodyStoreFromMaxBytesReader(store *ssa.Store, requestParam *ssa.Parameter, writerParam *ssa.Parameter) bool {
	fieldAddr, ok := store.Addr.(*ssa.FieldAddr)
	if !ok {
		return false
	}

	if !valueDependsOn(fieldAddr.X, requestParam, 0) {
		return false
	}

	if !isMaxBytesReaderValue(store.Val, requestParam, writerParam, 0) {
		return false
	}

	return true
}

func isMaxBytesReaderValue(v ssa.Value, requestParam *ssa.Parameter, writerParam *ssa.Parameter, depth int) bool {
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
		if !valueDependsOn(value.Call.Args[0], writerParam, 0) {
			return false
		}
		return valueDependsOn(value.Call.Args[1], requestParam, 0)
	case *ssa.ChangeType:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, depth+1)
	case *ssa.MakeInterface:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, depth+1)
	case *ssa.TypeAssert:
		return isMaxBytesReaderValue(value.X, requestParam, writerParam, depth+1)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			if isMaxBytesReaderValue(edge, requestParam, writerParam, depth+1) {
				return true
			}
		}
	}

	return false
}

func isRiskyFormParsingCall(callInstr ssa.CallInstruction, requestParam *ssa.Parameter) bool {
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

	return valueDependsOn(common.Args[0], requestParam, 0)
}
