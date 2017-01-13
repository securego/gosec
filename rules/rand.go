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

type WeakRand struct {
	gas.MetaData
	funcNames   []string
	packagePath string
}

func (w *WeakRand) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	for _, funcName := range w.funcNames {
		if _, matched := gas.MatchCallByPackage(n, c, w.packagePath, funcName); matched {
			return gas.NewIssue(c, n, w.What, w.Severity, w.Confidence), nil
		}
	}

	return nil, nil
}

func NewWeakRandCheck(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &WeakRand{
		funcNames:   []string{"Read", "Int"},
		packagePath: "math/rand",
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.Medium,
			What:       "Use of weak random number generator (math/rand instead of crypto/rand)",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
