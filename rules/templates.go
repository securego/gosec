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
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type TemplateCheck struct {
	gas.MetaData
	call *regexp.Regexp
}

func (t *TemplateCheck) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node := gas.MatchCall(n, t.call); node != nil {
		for _, arg := range node.Args {
			if _, ok := arg.(*ast.BasicLit); !ok { // basic lits are safe
				return gas.NewIssue(c, n, t.What, t.Severity, t.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewTemplateCheck(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &TemplateCheck{
		call: regexp.MustCompile(`^template\.(HTML|JS|URL)$`),
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.Low,
			What:       "this method will not auto-escape HTML. Verify data is well formed.",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
