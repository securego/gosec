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

	gas "github.com/HewlettPackard/gas/core"
)

type BlacklistImports struct {
	BlacklistSet map[string]gas.MetaData
}

func (r *BlacklistImports) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if data, ok := r.BlacklistSet[node.Path.Value]; ok {
			return gas.NewIssue(c, n, data.What, data.Severity, data.Confidence), nil
		}
	}
	return nil, nil
}

func NewBlacklistImports() (r gas.Rule, n ast.Node) {
	// TODO(tkelsey): make this configurable
	// TODO(tkelsey): make it so each item can be selected/excluded individually
	r = &BlacklistImports{
		BlacklistSet: map[string]gas.MetaData{
			`"crypto/md5"`: gas.MetaData{
				Severity:   gas.High,
				Confidence: gas.High,
				What:       "Use of weak cryptographic primitive",
			},
			`"crypto/des"`: gas.MetaData{
				Severity:   gas.High,
				Confidence: gas.High,
				What:       "Use of weak cryptographic primitive",
			},
			`"crypto/rc4"`: gas.MetaData{
				Severity:   gas.High,
				Confidence: gas.High,
				What:       "Use of weak cryptographic primitive",
			},
			`"net/http/cgi"`: gas.MetaData{
				Severity:   gas.High,
				Confidence: gas.Low,
				What:       "Go code running under CGI is vulnerable to Httpoxy attack. (CVE-2016-5386)",
			},
		},
	}

	n = (*ast.ImportSpec)(nil)
	return
}
