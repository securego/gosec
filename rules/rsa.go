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
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type WeakKeyStrength struct {
	gas.MetaData
	pattern *regexp.Regexp
	bits    int
}

func (w *WeakKeyStrength) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := gas.MatchCall(n, w.pattern); node != nil {
		if bits, err := gas.GetInt(node.Args[1]); err == nil && bits < (int64)(w.bits) {
			return gas.NewIssue(c, n, w.What, w.Severity, w.Confidence), nil
		}
	}
	return nil, nil
}

func NewWeakKeyStrength(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	bits := 2048
	return &WeakKeyStrength{
		pattern: regexp.MustCompile(`^rsa\.GenerateKey$`),
		bits:    bits,
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       fmt.Sprintf("RSA keys should be at least %d bits", bits),
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
