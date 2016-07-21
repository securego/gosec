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

	gas "github.com/HewlettPackard/gas/core"
)

// Looks for "import net/http/cgi"
type HttpoxyTest struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *HttpoxyTest) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if r.pattern.MatchString(node.Path.Value) {
			return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
		}
	}
	return
}

func NewHttpoxyTest() (r gas.Rule, n ast.Node) {
	r = &HttpoxyTest{
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.Low,
			What:       "Go code running under CGI is vulnerable to Httpoxy attack. (CVE-2016-5386)",
		},
		pattern: regexp.MustCompile("^\"net/http/cgi\"$"),
	}
	n = (*ast.ImportSpec)(nil)
	return
}
