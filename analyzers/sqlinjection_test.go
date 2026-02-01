// (c) Copyright gosec's authors
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

package analyzers

import (
	"os"
	"testing"

	"github.com/securego/gosec/v2/analyzers/taint"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// buildSSA builds SSA from Go source code for testing
func buildSSA(t *testing.T, src string) (*ssa.Program, []*ssa.Function) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(dir+"/go.mod", []byte("module test\ngo 1.21"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/main.go", []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: dir}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatal(err)
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.SanityCheckFunctions)
	prog.Build()

	var funcs []*ssa.Function
	for _, pkg := range ssaPkgs {
		if pkg != nil {
			for _, m := range pkg.Members {
				if fn, ok := m.(*ssa.Function); ok {
					funcs = append(funcs, fn)
					funcs = append(funcs, fn.AnonFuncs...)
				}
			}
		}
	}
	return prog, funcs
}

func TestAnalyzeRealSQLInjection(t *testing.T) {
	src := `package main
import ("database/sql"; "net/http")
func handler(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}`

	prog, funcs := buildSSA(t, src)
	config := taint.SQLInjection()
	analyzer := taint.New(&config)
	results := analyzer.Analyze(prog, funcs)

	if len(results) == 0 {
		t.Error("expected SQL injection detection")
	}
}

func TestAnalyzeSafeCode(t *testing.T) {
	src := `package main
import "database/sql"
func handler(db *sql.DB) {
	db.Query("SELECT * FROM users")
}`

	prog, funcs := buildSSA(t, src)
	config := taint.SQLInjection()
	analyzer := taint.New(&config)
	results := analyzer.Analyze(prog, funcs)

	if len(results) != 0 {
		t.Error("unexpected false positive")
	}
}
