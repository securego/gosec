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
)

type UsingUnsafe struct {
	gas.MetaData
	pkg   string
	calls []string
}

func (r *UsingUnsafe) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if _, matches := gas.MatchCallByPackage(n, c, r.pkg, r.calls...); matches {
		return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
	}
	return nil, nil
}

func NewUsingUnsafe(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &UsingUnsafe{
		pkg:   "unsafe",
		calls: []string{"Alignof", "Offsetof", "Sizeof", "Pointer"},
		MetaData: gas.MetaData{
			What:       "Use of unsafe calls should be audited",
			Severity:   gas.Low,
			Confidence: gas.High,
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
