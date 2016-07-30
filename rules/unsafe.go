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

type UsingUnsafe struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *UsingUnsafe) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node := gas.MatchCall(n, r.pattern); node != nil {
		return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
	}
	return nil, nil
}

func NewUsingUnsafe() (r gas.Rule, n ast.Node) {
	r = &UsingUnsafe{
		pattern: regexp.MustCompile(`unsafe.*`),
		MetaData: gas.MetaData{
			What:       "Use of unsafe calls should be audited",
			Severity:   gas.Low,
			Confidence: gas.High,
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}
