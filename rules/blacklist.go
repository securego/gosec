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

	gas "github.com/GoASTScanner/gas/core"
)

type BlacklistImport struct {
	gas.MetaData
	Path string
}

func (r *BlacklistImport) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		if r.Path == node.Path.Value && node.Name.String() != "_" {
			return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

func NewBlacklist_crypto_md5(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &BlacklistImport{
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.High,
			What:       "Use of weak cryptographic primitive",
		},
		Path: `"crypto/md5"`,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

func NewBlacklist_crypto_des(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &BlacklistImport{
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.High,
			What:       "Use of weak cryptographic primitive",
		},
		Path: `"crypto/des"`,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

func NewBlacklist_crypto_rc4(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &BlacklistImport{
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.High,
			What:       "Use of weak cryptographic primitive",
		},
		Path: `"crypto/rc4"`,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

func NewBlacklist_net_http_cgi(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &BlacklistImport{
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.High,
			What:       "Go versions < 1.6.3 are vulnerable to Httpoxy attack: (CVE-2016-5386)",
		},
		Path: `"net/http/cgi"`,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}
