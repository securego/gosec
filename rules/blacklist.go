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

	"github.com/GoASTScanner/gas"
)

type blacklistedImport struct {
	gas.MetaData
	Blacklisted map[string]string
}

func (r *blacklistedImport) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node, ok := n.(*ast.ImportSpec); ok {
		description, ok := r.Blacklisted[node.Path.Value]
		if ok && node.Name.String() != "_" {
			return gas.NewIssue(c, n, description, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

// NewBlacklistedImports reports when a blacklisted import is being used.
// Typically when a deprecated technology is being used.
func NewBlacklistedImports(conf gas.Config, blacklist map[string]string) (gas.Rule, []ast.Node) {
	return &blacklistedImport{
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
		},
		Blacklisted: blacklist,
	}, []ast.Node{(*ast.ImportSpec)(nil)}
}

// NewBlacklistedImportMD5 fails if MD5 is imported
func NewBlacklistedImportMD5(conf gas.Config) (gas.Rule, []ast.Node) {
	return NewBlacklistedImports(conf, map[string]string{
		"crypto/md5": "Use of weak cryptographic primitive",
	})
}

// NewBlacklistedImportDES fails if DES is imported
func NewBlacklistedImportDES(conf gas.Config) (gas.Rule, []ast.Node) {
	return NewBlacklistedImports(conf, map[string]string{
		"crypto/des": "Use of weak cryptographic primitive",
	})
}

// NewBlacklistedImportRC4 fails if DES is imported
func NewBlacklistedImportRC4(conf gas.Config) (gas.Rule, []ast.Node) {
	return NewBlacklistedImports(conf, map[string]string{
		"crypto/rc4": "Use of weak cryptographic primitive",
	})
}

// NewBlacklistedImportCGI fails if CGI is imported
func NewBlacklistedImportCGI(conf gas.Config) (gas.Rule, []ast.Node) {
	return NewBlacklistedImports(conf, map[string]string{
		"net/http/cgi": "Go versions < 1.6.3 are vulnerable to Httpoxy attack: (CVE-2016-5386)",
	})
}
