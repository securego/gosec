// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

package rules

import (
	gas "github.com/GoASTScanner/gas/core"
	"go/ast"
	"go/token"
	"regexp"
)

type Credentials struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *Credentials) Match(n ast.Node, ctx *gas.Context) (*gas.Issue, error) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return r.matchAssign(node, ctx)
	case *ast.GenDecl:
		return r.matchGenDecl(node, ctx)
	}
	return nil, nil
}

func (r *Credentials) matchAssign(assign *ast.AssignStmt, ctx *gas.Context) (*gas.Issue, error) {
	for _, i := range assign.Lhs {
		if ident, ok := i.(*ast.Ident); ok {
			if r.pattern.MatchString(ident.Name) {
				for _, e := range assign.Rhs {
					if _, ok := e.(*ast.BasicLit); ok {
						return gas.NewIssue(ctx, assign, r.What, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func (r *Credentials) matchGenDecl(decl *ast.GenDecl, ctx *gas.Context) (*gas.Issue, error) {
	if decl.Tok != token.CONST && decl.Tok != token.VAR {
		return nil, nil
	}
	for _, spec := range decl.Specs {
		if valueSpec, ok := spec.(*ast.ValueSpec); ok {
			for index, ident := range valueSpec.Names {
				if r.pattern.MatchString(ident.Name) && valueSpec.Values != nil {
					// const foo, bar = "same value"
					if len(valueSpec.Values) <= index {
						index = len(valueSpec.Values) - 1
					}
					if _, ok := valueSpec.Values[index].(*ast.BasicLit); ok {
						return gas.NewIssue(ctx, decl, r.What, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewHardcodedCredentials(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	pattern := `(?i)passwd|pass|password|pwd|secret|token`
	if val, ok := conf["G101"]; ok {
		pattern = val.(string)
	}
	return &Credentials{
		pattern: regexp.MustCompile(pattern),
		MetaData: gas.MetaData{
			What:       "Potential hardcoded credentials",
			Confidence: gas.Low,
			Severity:   gas.High,
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.GenDecl)(nil)}
}
