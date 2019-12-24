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
	"github.com/securego/gosec"
	"go/ast"
)

type integerOverflowCheck struct {
	gosec.MetaData
	calls gosec.CallList
}

func (i *integerOverflowCheck) ID() string {
	return i.MetaData.ID
}

func (i *integerOverflowCheck) Match(node ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	varName := make(map[string]ast.Node)
	var issue *gosec.Issue

	// strconv.Atoi is a common function.
	// To reduce false positives, This code detects code which is converted to int32/int16 only.
	match := func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, expr := range n.Rhs {
				if callExpr, ok := expr.(*ast.CallExpr); ok && i.calls.ContainsCallExpr(callExpr, ctx, false) != nil {
					if id, ok := n.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
						// Example:
						//  v, _ := strconv.Atoi("1111")
						// Add "v" to varName map
						varName[id.Name] = n
					}
				}
			}
		case *ast.CallExpr:
			if fun, ok := n.Fun.(*ast.Ident); ok {
				if fun.Name == "int32" || fun.Name == "int16" {
					if idt, ok := n.Args[0].(*ast.Ident); ok {
						if n, ok := varName[idt.Name]; ok {
							// Detect int32(v) and int16(v)
							issue = gosec.NewIssue(ctx, n, i.ID(), i.What, i.Severity, i.Confidence)
							return false
						}
					}
				}
			}
		}
		return true
	}

	ast.Inspect(node, match)

	if issue != nil {
		return issue, nil
	}
	return nil, nil
}

// NewIntegerOverflowCheck detects if there is potential Integer OverFlow
func NewIntegerOverflowCheck(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("strconv", "Atoi")
	return &integerOverflowCheck{
		MetaData: gosec.MetaData{
			ID:         id,
			Severity:   gosec.High,
			Confidence: gosec.Medium,
			What:       "Potential Integer overflow made by strconv.Atoi result conversion to int16/32",
		},
		calls: calls,
	}, []ast.Node{(*ast.FuncDecl)(nil)}
}
