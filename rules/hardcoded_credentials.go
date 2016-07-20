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
	gas "github.com/HewlettPackard/gas/core"
	"go/ast"
	"regexp"
)

type CredsAssign struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *CredsAssign) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.AssignStmt); ok {
		for _, i := range node.Lhs {
			if ident, ok := i.(*ast.Ident); ok {
				if r.pattern.MatchString(ident.Name) {
					gi = gas.NewIssue(c, n, r.What, r.Severity, r.Confidence)
					break
				}
			}
		}
	}
	return
}

func NewHardcodedCredentials() (r gas.Rule, n ast.Node) {
	r = &CredsAssign{
		pattern: regexp.MustCompile("(?i)passwd|pass|password|pwd|secret|token"),
		MetaData: gas.MetaData{
			What:       "Potential hardcoded credentials",
			Confidence: gas.Low,
			Severity:   gas.High,
		},
	}
	n = (*ast.AssignStmt)(nil)
	return
}
