package taint

import (
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

func TestMakeAnalyzerRunnerReturnsErrorWithoutSSA(t *testing.T) {
	t.Parallel()

	rule := &RuleInfo{ID: "T001", Description: "desc", Severity: "HIGH"}
	runner := makeAnalyzerRunner(rule, &Config{})

	pass := &analysis.Pass{ResultOf: map[*analysis.Analyzer]interface{}{}}
	if _, err := runner(pass); err == nil {
		t.Fatalf("expected error when SSA result is missing")
	}
}

func TestMakeAnalyzerRunnerReturnsNilWhenNoSourceFunctions(t *testing.T) {
	t.Parallel()

	rule := &RuleInfo{ID: "T001", Description: "desc", Severity: "HIGH"}
	runner := makeAnalyzerRunner(rule, &Config{})

	pass := &analysis.Pass{
		ResultOf: map[*analysis.Analyzer]interface{}{
			buildssa.Analyzer: &ssautil.SSAAnalyzerResult{SSA: &buildssa.SSA{}},
		},
	}

	got, err := runner(pass)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result when no source functions exist")
	}
}

func TestNewIssuePopulatesFields(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "main.go")
	src := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"
	if err := os.WriteFile(filePath, []byte(src), 0o600); err != nil {
		t.Fatalf("failed to write temp source: %v", err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}

	iss := newIssue("T001", "taint finding", fset, parsed.Package, issue.High, issue.High)
	if iss.RuleID != "T001" {
		t.Fatalf("unexpected rule id: %s", iss.RuleID)
	}
	if iss.File != filePath {
		t.Fatalf("unexpected file path: %s", iss.File)
	}
	if iss.Line != "1" || iss.Col != "1" {
		t.Fatalf("unexpected location: line=%s col=%s", iss.Line, iss.Col)
	}
	if iss.What != "taint finding" {
		t.Fatalf("unexpected description: %s", iss.What)
	}
}

func TestIssueCodeSnippetReadsSource(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "snippet.go")
	src := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"
	if err := os.WriteFile(filePath, []byte(src), 0o600); err != nil {
		t.Fatalf("failed to write temp source: %v", err)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}

	snippet := issueCodeSnippet(fset, parsed.Package)
	if snippet == "" {
		t.Fatalf("expected non-empty snippet")
	}
}

func TestIsContextTypeWithContextContext(t *testing.T) {
	t.Parallel()

	// Build a context.Context named type matching the real context package.
	pkg := types.NewPackage("context", "context")
	iface := types.NewInterfaceType(nil, nil)
	obj := types.NewTypeName(token.NoPos, pkg, "Context", nil)
	named := types.NewNamed(obj, iface, nil)

	if !isContextType(named) {
		t.Fatalf("expected isContextType to return true for context.Context")
	}
}

func TestIsContextTypeWithPointerToContextContext(t *testing.T) {
	t.Parallel()

	pkg := types.NewPackage("context", "context")
	iface := types.NewInterfaceType(nil, nil)
	obj := types.NewTypeName(token.NoPos, pkg, "Context", nil)
	named := types.NewNamed(obj, iface, nil)
	ptr := types.NewPointer(named)

	if !isContextType(ptr) {
		t.Fatalf("expected isContextType to return true for *context.Context")
	}
}

func TestIsContextTypeRejectsNonContextTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  types.Type
	}{
		{
			name: "http.Request",
			typ: func() types.Type {
				pkg := types.NewPackage("net/http", "http")
				obj := types.NewTypeName(token.NoPos, pkg, "Request", nil)
				return types.NewNamed(obj, types.NewStruct(nil, nil), nil)
			}(),
		},
		{
			name: "string",
			typ:  types.Typ[types.String],
		},
		{
			name: "wrong package same name",
			typ: func() types.Type {
				pkg := types.NewPackage("myapp/context", "context")
				obj := types.NewTypeName(token.NoPos, pkg, "Context", nil)
				return types.NewNamed(obj, types.NewInterfaceType(nil, nil), nil)
			}(),
		},
		{
			name: "context package wrong name",
			typ: func() types.Type {
				pkg := types.NewPackage("context", "context")
				obj := types.NewTypeName(token.NoPos, pkg, "CancelFunc", nil)
				return types.NewNamed(obj, types.Typ[types.String], nil)
			}(),
		},
		{
			name: "pointer to non-context type",
			typ: func() types.Type {
				pkg := types.NewPackage("net/http", "http")
				obj := types.NewTypeName(token.NoPos, pkg, "Request", nil)
				return types.NewPointer(types.NewNamed(obj, types.NewStruct(nil, nil), nil))
			}(),
		},
		{
			name: "nil type",
			typ:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isContextType(tc.typ) {
				t.Fatalf("expected isContextType to return false for %s", tc.name)
			}
		})
	}
}

func TestNewIssueReturnsEmptyWhenPositionCannotBeResolved(t *testing.T) {
	t.Parallel()

	iss := newIssue("T001", "desc", token.NewFileSet(), token.NoPos, issue.High, issue.High)
	if iss.RuleID != "" || iss.File != "" {
		t.Fatalf("expected empty issue for unresolved position, got %+v", iss)
	}
}
