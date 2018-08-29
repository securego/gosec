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

	"github.com/GoASTScanner/gas"
)

type ssrf struct {
	gas.MetaData
	gas.CallList
}

// ID returns the identifier for this rule
func (r *ssrf) ID() string {
	return r.MetaData.ID
}

//	TODO(jovon) identify these calls from type `http.Client`
//		- https://github.com/go-resty/resty -- looks well maintained and popular
//
// Match inspects AST nodes to determine if certain net/http methods are called with variable input
func (r *ssrf) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := r.ContainsCallExpr(n, c); node != nil {
		for _, arg := range node.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				obj := c.Info.ObjectOf(ident)
				if _, ok := obj.(*types.Var); ok && !gas.TryResolve(ident, c) {
					return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewSSRFCheck detects cases where HTTP requests are sent
func NewSSRFCheck(id string, conf gas.Config) (gas.Rule, []ast.Node) {
	rule := &readfile{
		CallList: gas.NewCallList(),
		MetaData: gas.MetaData{
			ID:         id,
			What:       "Potential HTTP request made with variable url",
			Severity:   gas.Medium,
			Confidence: gas.High,
		},
	}
	rule.Add("net/http", "Do")
	rule.Add("net/http", "Get")
	rule.Add("net/http", "Head")
	rule.Add("net/http", "Post")
	rule.Add("net/http", "PostForm")
	rule.Add("net/http", "RoundTrip")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
