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
	"strings"

	gas "github.com/GoASTScanner/gas/core"
)

type WeakRand struct {
	gas.MetaData
	pattern     *regexp.Regexp
	packagePath string
}

type pkgFunc struct {
	packagePath string
	funcName    string
}

// pkgId takes an import line and returns the identifier used
// for that package in the rest of the file
func pkgId(i *ast.ImportSpec) string {
	if i.Name != nil {
		return i.Name.String()
	}
	trim := strings.Trim(i.Path.Value, `"`)
	a := strings.Split(trim, "/")
	return a[len(a)-1]
}

// importIds returns a map of import names to their full paths
func importIds(f *ast.File) map[string]string {
	pkgs := make(map[string]string)
	for _, v := range f.Imports {
		pkgs[pkgId(v)] = strings.Trim(v.Path.Value, `"`)
	}
	return pkgs
}

// matchPkgFunc will return package level function calls split
// by full package path and function name
func matchPkgFunc(n ast.Node, c *gas.Context) *pkgFunc {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}

	if id.Obj != nil {
		return nil
	}

	i := importIds(c.Root)
	v, ok := i[id.Name]
	if !ok {
		return nil
	}

	return &pkgFunc{
		packagePath: v,
		funcName:    sel.Sel.String(),
	}
}

func (w *WeakRand) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	call := matchPkgFunc(n, c)

	if call != nil && call.packagePath == w.packagePath && w.pattern.MatchString(call.funcName) {
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
