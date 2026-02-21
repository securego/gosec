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

package goanalysis

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/analysis"

	"github.com/securego/gosec/v2/issue"
)

func TestBuildFilters(t *testing.T) {
	t.Parallel()

	newFilter := func(exclude bool, ids ...string) string {
		prefix := "include"
		if exclude {
			prefix = "exclude"
		}
		return prefix + ":" + ids[0]
	}

	filters := buildFilters(" G101 , , G102 ", "G201", newFilter)
	if len(filters) != 2 {
		t.Fatalf("unexpected filter count: got %d want 2", len(filters))
	}
	if filters[0] != "include:G101" {
		t.Fatalf("unexpected include filter: %q", filters[0])
	}
	if filters[1] != "exclude:G201" {
		t.Fatalf("unexpected exclude filter: %q", filters[1])
	}
}

func TestParseRuleIDs(t *testing.T) {
	t.Parallel()

	ids := parseRuleIDs(" G101, ,G102,,  G115 ")
	if len(ids) != 3 {
		t.Fatalf("unexpected ids count: got %d want 3", len(ids))
	}
	if ids[0] != "G101" || ids[1] != "G102" || ids[2] != "G115" {
		t.Fatalf("unexpected ids: %v", ids)
	}
}

func TestParseScore(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want issue.Score
	}{
		{in: "low", want: issue.Low},
		{in: "Medium", want: issue.Medium},
		{in: "HIGH", want: issue.High},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseScore(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("unexpected score: got %v want %v", got, tc.want)
			}
		})
	}

	if _, err := parseScore("critical"); err == nil {
		t.Fatalf("expected error for invalid score")
	}
}

func TestParsePosition(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	src := "package p\n\nfunc main() {\n\tprintln(\"x\")\n}\n"
	file, err := parser.ParseFile(fset, "/tmp/p.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}

	t.Run("uses start line for ranges", func(t *testing.T) {
		t.Parallel()

		iss := &issue.Issue{File: "/tmp/p.go", Line: "3-4", Col: "2"}
		pos := parsePosition(fset, iss)
		if pos == token.NoPos {
			t.Fatalf("expected valid position")
		}
		p := fset.Position(pos)
		if p.Line != 3 || p.Column != 2 {
			t.Fatalf("unexpected position: line=%d col=%d", p.Line, p.Column)
		}
	})

	t.Run("falls back to line start for invalid column", func(t *testing.T) {
		t.Parallel()

		iss := &issue.Issue{File: "/tmp/p.go", Line: "3", Col: "bad"}
		pos := parsePosition(fset, iss)
		p := fset.Position(pos)
		if p.Line != 3 || p.Column != 1 {
			t.Fatalf("unexpected fallback position: line=%d col=%d", p.Line, p.Column)
		}
	})

	t.Run("returns no position for unknown file", func(t *testing.T) {
		t.Parallel()

		iss := &issue.Issue{File: "/tmp/unknown.go", Line: "1", Col: "1"}
		if got := parsePosition(fset, iss); got != token.NoPos {
			t.Fatalf("expected NoPos, got %v", got)
		}
	})

	t.Run("returns no position for invalid line", func(t *testing.T) {
		t.Parallel()

		iss := &issue.Issue{File: "/tmp/p.go", Line: "99", Col: "1"}
		if got := parsePosition(fset, iss); got != token.NoPos {
			t.Fatalf("expected NoPos, got %v", got)
		}
	})

	_ = file
}

func TestConvertPassToPackage(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	src := "package p\n\nfunc main() {}\n"
	astFile, err := parser.ParseFile(fset, "/tmp/main.go", src, 0)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}

	pass := &analysis.Pass{
		Fset:  fset,
		Files: []*ast.File{},
		Pkg:   types.NewPackage("example.com/p", "p"),
	}
	pass.Files = append(pass.Files, astFile)

	pkg := convertPassToPackage(pass)
	if pkg.Name != "p" {
		t.Fatalf("unexpected package name: %q", pkg.Name)
	}
	if len(pkg.CompiledGoFiles) != 1 {
		t.Fatalf("unexpected file count: %d", len(pkg.CompiledGoFiles))
	}
	if pkg.CompiledGoFiles[0] != "/tmp/main.go" {
		t.Fatalf("unexpected compiled file path: %q", pkg.CompiledGoFiles[0])
	}
}
