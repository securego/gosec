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

package gas

import (
	"go/ast"
	"go/types"
	"strings"
)

type ImportTracker struct {
	Imported map[string]string
	Aliased  map[string]string
	InitOnly map[string]bool
}

func NewImportTracker() *ImportTracker {
	return &ImportTracker{
		make(map[string]string),
		make(map[string]string),
		make(map[string]bool),
	}
}

func (t *ImportTracker) TrackPackages(pkgs ...*types.Package) {
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports() {
			t.Imported[imp.Path()] = imp.Name()
		}
	}
}

func (t *ImportTracker) TrackImport(n ast.Node) {
	if imported, ok := n.(*ast.ImportSpec); ok {
		path := strings.Trim(imported.Path.Value, `"`)
		if imported.Name != nil {
			if imported.Name.Name == "_" {
				// Initialization only import
				t.InitOnly[path] = true
			} else {
				// Aliased import
				t.Aliased[path] = imported.Name.Name
			}
		}

		// unsafe is not included in Package.Imports()
		if path == "unsafe" {
			t.Imported[path] = path
		}
	}
}
