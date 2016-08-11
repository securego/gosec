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
	"go/ast"
	"go/types"
	"reflect"

	gas "github.com/HewlettPackard/gas/core"
)

type NoErrorCheck struct {
	gas.MetaData
}

func (r *NoErrorCheck) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.AssignStmt); ok {
		sel := reflect.TypeOf(&ast.CallExpr{})
		if call, ok := gas.SimpleSelect(node.Rhs[0], sel).(*ast.CallExpr); ok {
			if t := c.Info.Types[call].Type; t != nil {
				if typeVal, typeErr := t.(*types.Tuple); typeErr {
					for i := 0; i < typeVal.Len(); i++ {
						if typeVal.At(i).Type().String() == "error" { // TODO(tkelsey): is there a better way?
							if id, ok := node.Lhs[i].(*ast.Ident); ok && id.Name == "_" {
								return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
							}
						}
					}
				} else if t.String() == "error" { // TODO(tkelsey): is there a better way?
					if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name == "_" {
						return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func NewNoErrorCheck(conf map[string]interface{}) (r gas.Rule, n ast.Node) {
	r = &NoErrorCheck{
		MetaData: gas.MetaData{
			Severity:   gas.Low,
			Confidence: gas.High,
			What:       "Errors unhandled.",
		},
	}
	n = (*ast.AssignStmt)(nil)
	return
}
