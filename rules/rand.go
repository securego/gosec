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
	"go/types"
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type WeakRand struct {
	gas.MetaData
	pattern     *regexp.Regexp
	packagePath string
}

func matchFuncCall(n ast.Node, c *gas.Context) (types.Object, *ast.Ident) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}

	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	return c.Info.ObjectOf(id), sel.Sel
}

func (w *WeakRand) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	o, f := matchFuncCall(n, c)

	if o == nil || f == nil {
		return nil, nil
	}

	pkg, ok := o.(*types.PkgName)
	if !ok {
		return nil, nil
	}

	if pkg.Imported().Path() == w.packagePath && w.pattern.MatchString(f.String()) {
		return gas.NewIssue(c, n, w.What, w.Severity, w.Confidence), nil
	}

	return nil, nil
}

func NewWeakRandCheck(conf map[string]interface{}) (r gas.Rule, n ast.Node) {
	r = &WeakRand{
		pattern:     regexp.MustCompile(`^Read$`),
		packagePath: "math/rand",
		MetaData: gas.MetaData{
			Severity:   gas.High,
			Confidence: gas.Medium,
			What:       "Use of weak random number generator (math/rand instead of crypto/rand)",
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}
