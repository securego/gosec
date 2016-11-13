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
	"fmt"
	"go/ast"
	"reflect"
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type InsecureConfigTLS struct {
	MinVersion  int16
	MaxVersion  int16
	pattern     *regexp.Regexp
	goodCiphers []string
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (t *InsecureConfigTLS) processTlsCipherSuites(n ast.Node, c *gas.Context) *gas.Issue {
	a := reflect.TypeOf(&ast.KeyValueExpr{})
	b := reflect.TypeOf(&ast.CompositeLit{})
	if node, ok := gas.SimpleSelect(n, a, b).(*ast.CompositeLit); ok {
		for _, elt := range node.Elts {
			if ident, ok := elt.(*ast.SelectorExpr); ok {
				if !stringInSlice(ident.Sel.Name, t.goodCiphers) {
					str := fmt.Sprintf("TLS Bad Cipher Suite: %s", ident.Sel.Name)
					return gas.NewIssue(c, n, str, gas.High, gas.High)
				}
			}
		}
	}
	return nil
}

func (t *InsecureConfigTLS) processTlsConfVal(n *ast.KeyValueExpr, c *gas.Context) *gas.Issue {
	if ident, ok := n.Key.(*ast.Ident); ok {
		switch ident.Name {
		case "InsecureSkipVerify":
			if node, ok := n.Value.(*ast.Ident); ok {
				if node.Name != "false" {
					return gas.NewIssue(c, n, "TLS InsecureSkipVerify set true.", gas.High, gas.High)
				}
			} else {
				// TODO(tk): symbol tab look up to get the actual value
				return gas.NewIssue(c, n, "TLS InsecureSkipVerify may be true.", gas.High, gas.Low)
			}

		case "MinVersion":
			if ival, ierr := gas.GetInt(n.Value); ierr == nil {
				if (int16)(ival) < t.MinVersion {
					return gas.NewIssue(c, n, "TLS MinVersion too low.", gas.High, gas.High)
				}
				// TODO(tk): symbol tab look up to get the actual value
				return gas.NewIssue(c, n, "TLS MinVersion may be too low.", gas.High, gas.Low)
			}

		case "MaxVersion":
			if ival, ierr := gas.GetInt(n.Value); ierr == nil {
				if (int16)(ival) < t.MaxVersion {
					return gas.NewIssue(c, n, "TLS MaxVersion too low.", gas.High, gas.High)
				}
				// TODO(tk): symbol tab look up to get the actual value
				return gas.NewIssue(c, n, "TLS MaxVersion may be too low.", gas.High, gas.Low)
			}

		case "CipherSuites":
			if ret := t.processTlsCipherSuites(n, c); ret != nil {
				return ret
			}
		}
	}
	return nil
}

func (t *InsecureConfigTLS) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node := gas.MatchCompLit(n, t.pattern); node != nil {
		for _, elt := range node.Elts {
			if kve, ok := elt.(*ast.KeyValueExpr); ok {
				gi = t.processTlsConfVal(kve, c)
				if gi != nil {
					break
				}
			}
		}
	}
	return
}

func NewModernTlsCheck(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	// https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
	return &InsecureConfigTLS{
		pattern:    regexp.MustCompile(`^tls\.Config$`),
		MinVersion: 0x0303, // TLS 1.2 only
		MaxVersion: 0x0303,
		goodCiphers: []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}

func NewIntermediateTlsCheck(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	// https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29
	return &InsecureConfigTLS{
		pattern:    regexp.MustCompile(`^tls\.Config$`),
		MinVersion: 0x0301, // TLS 1.2, 1.1, 1.0
		MaxVersion: 0x0303,
		goodCiphers: []string{
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}

func NewCompatTlsCheck(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	// https://wiki.mozilla.org/Security/Server_Side_TLS#Old_compatibility_.28default.29
	return &InsecureConfigTLS{
		pattern:    regexp.MustCompile(`^tls\.Config$`),
		MinVersion: 0x0301, // TLS 1.2, 1.1, 1.0
		MaxVersion: 0x0303,
		goodCiphers: []string{
			"TLS_RSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}
