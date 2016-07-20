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
	"reflect"
	"regexp"
)

type ImportsWeakCryptography struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *ImportsWeakCryptography) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	a := reflect.TypeOf(&ast.ImportSpec{})
	b := reflect.TypeOf(&ast.BasicLit{})
	if node := gas.SimpleSelect(n, a, b); node != nil {
		if str, _ := gas.GetString(node); r.pattern.MatchString(str) {
			return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
		}
	}
	return
}

// Imports crypto/md5, crypto/des crypto/rc4
func NewImportsWeakCryptography() (r gas.Rule, n ast.Node) {
	r = &ImportsWeakCryptography{
		pattern: regexp.MustCompile("crypto/md5|crypto/des|crypto/rc4"),
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       "Import of weak cryptographic primitive",
		},
	}
	n = (*ast.ImportSpec)(nil)
	return
}

type UsesWeakCryptography struct {
	gas.MetaData
	pattern *regexp.Regexp
}

func (r *UsesWeakCryptography) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := gas.MatchCall(n, r.pattern); node != nil {
		return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
	}
	return nil, nil
}

// Uses des.* md5.* or rc4.*
func NewUsesWeakCryptography() (r gas.Rule, n ast.Node) {
	r = &UsesWeakCryptography{
		pattern: regexp.MustCompile("des.NewCipher|des.NewTripleDESCipher|md5.New|md5.Sum|rc4.NewCipher"),
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       "Use of weak cryptographic primitive",
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}
