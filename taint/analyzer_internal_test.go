package taint

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

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

// ── lookupNamedType ───────────────────────────────────────────────────────────

func TestLookupNamedTypeNoDot(t *testing.T) {
	t.Parallel()
	// A path with no dot must return nil before touching prog.
	if got := lookupNamedType("nodot", nil); got != nil {
		t.Fatalf("expected nil for path with no dot, got %v", got)
	}
}

func TestLookupNamedTypePackageNotInProgram(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)
	// Program is empty — the requested package is not present.
	if got := lookupNamedType("net/http.ResponseWriter", prog); got != nil {
		t.Fatalf("expected nil when package is absent from program, got %v", got)
	}
}

func TestLookupNamedTypeFound(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Manually construct a net/http package with ResponseWriter in its scope.
	httpPkg := types.NewPackage("net/http", "http")
	iface := types.NewInterfaceType(nil, nil)
	obj := types.NewTypeName(token.NoPos, httpPkg, "ResponseWriter", nil)
	_ = types.NewNamed(obj, iface, nil)
	httpPkg.Scope().Insert(obj)
	httpPkg.MarkComplete()
	prog.CreatePackage(httpPkg, nil, nil, false)

	got := lookupNamedType("net/http.ResponseWriter", prog)
	if got == nil {
		t.Fatal("expected non-nil type for known type in program")
	}
	named, ok := got.(*types.Named)
	if !ok {
		t.Fatalf("expected *types.Named, got %T", got)
	}
	if named.Obj().Name() != "ResponseWriter" {
		t.Fatalf("expected name ResponseWriter, got %s", named.Obj().Name())
	}
}

func TestLookupNamedTypeMemberIsNotTypeName(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Insert a Var (not a TypeName) into the package scope.
	pkg := types.NewPackage("mylib", "mylib")
	varObj := types.NewVar(token.NoPos, pkg, "SomeVar", types.Typ[types.String])
	pkg.Scope().Insert(varObj)
	pkg.MarkComplete()
	prog.CreatePackage(pkg, nil, nil, false)

	// SomeVar is a *types.Var, not a *types.TypeName — lookup must return nil.
	if got := lookupNamedType("mylib.SomeVar", prog); got != nil {
		t.Fatalf("expected nil for non-TypeName member, got %v", got)
	}
}

func TestLookupNamedTypeMemberNotInScope(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Package with the right path but the requested name is absent from scope.
	pkg := types.NewPackage("net/http", "http")
	pkg.MarkComplete()
	prog.CreatePackage(pkg, nil, nil, false)

	// "Missing" is not in scope — exercises the member==nil continue branch.
	if got := lookupNamedType("net/http.Missing", prog); got != nil {
		t.Fatalf("expected nil for absent type name, got %v", got)
	}
}

// ── guardsSatisfied ───────────────────────────────────────────────────────────

func TestGuardsSatisfiedEmptyGuards(t *testing.T) {
	t.Parallel()
	if !guardsSatisfied(nil, Sink{}, nil) {
		t.Fatal("expected true for empty ArgTypeGuards")
	}
}

func TestGuardsSatisfiedNilProg(t *testing.T) {
	t.Parallel()
	sink := Sink{ArgTypeGuards: map[int]string{0: "net/http.ResponseWriter"}}
	if !guardsSatisfied(nil, sink, nil) {
		t.Fatal("expected true when prog is nil")
	}
}

func TestGuardsSatisfiedArgIdxOutOfRange(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)
	sink := Sink{ArgTypeGuards: map[int]string{0: "net/http.ResponseWriter"}}
	// Guard requires arg at index 0 but args slice is empty.
	if guardsSatisfied([]ssa.Value{}, sink, prog) {
		t.Fatal("expected false when arg index is out of range")
	}
}

func TestGuardsSatisfiedRequiredTypeNotFound(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)
	// Guard refers to a type that is not present in the program.
	// The guard must not be satisfied.
	sink := Sink{ArgTypeGuards: map[int]string{0: "missing/pkg.Type"}}
	arg := ssa.NewConst(constant.MakeString("x"), types.Typ[types.String])
	if guardsSatisfied([]ssa.Value{arg}, sink, prog) {
		t.Fatal("expected false when required type is not found")
	}
}

func TestGuardsSatisfiedInterfaceNotSatisfied(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Build an interface with one method; string doesn't implement it.
	pkg := types.NewPackage("io", "io")
	sig := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	closeMethod := types.NewFunc(token.NoPos, pkg, "Close", sig)
	closerIface := types.NewInterfaceType([]*types.Func{closeMethod}, nil)
	closerIface.Complete()
	obj := types.NewTypeName(token.NoPos, pkg, "Closer", nil)
	_ = types.NewNamed(obj, closerIface, nil)
	pkg.Scope().Insert(obj)
	pkg.MarkComplete()
	prog.CreatePackage(pkg, nil, nil, false)

	arg := ssa.NewConst(constant.MakeString("x"), types.Typ[types.String])
	sink := Sink{ArgTypeGuards: map[int]string{0: "io.Closer"}}
	if guardsSatisfied([]ssa.Value{arg}, sink, prog) {
		t.Fatal("expected false when arg type does not implement required interface")
	}
}

func TestGuardsSatisfiedEmptyInterfaceSatisfied(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Empty interface — every type satisfies it.
	pkg := types.NewPackage("any/pkg", "pkg")
	emptyIface := types.NewInterfaceType(nil, nil)
	emptyIface.Complete()
	obj := types.NewTypeName(token.NoPos, pkg, "AnyType", nil)
	_ = types.NewNamed(obj, emptyIface, nil)
	pkg.Scope().Insert(obj)
	pkg.MarkComplete()
	prog.CreatePackage(pkg, nil, nil, false)

	arg := ssa.NewConst(constant.MakeString("x"), types.Typ[types.String])
	sink := Sink{ArgTypeGuards: map[int]string{0: "any/pkg.AnyType"}}
	if !guardsSatisfied([]ssa.Value{arg}, sink, prog) {
		t.Fatal("expected true when arg implements empty interface")
	}
}

func TestGuardsSatisfiedConcreteTypeNotSatisfied(t *testing.T) {
	t.Parallel()
	prog := ssa.NewProgram(token.NewFileSet(), 0)

	// Named struct type — string is not identical to it.
	pkg := types.NewPackage("myapp", "myapp")
	obj := types.NewTypeName(token.NoPos, pkg, "MyStruct", nil)
	_ = types.NewNamed(obj, types.NewStruct(nil, nil), nil)
	pkg.Scope().Insert(obj)
	pkg.MarkComplete()
	prog.CreatePackage(pkg, nil, nil, false)

	arg := ssa.NewConst(constant.MakeString("x"), types.Typ[types.String])
	sink := Sink{ArgTypeGuards: map[int]string{0: "myapp.MyStruct"}}
	// string != myapp.MyStruct and string != *myapp.MyStruct → guard not satisfied.
	if guardsSatisfied([]ssa.Value{arg}, sink, prog) {
		t.Fatal("expected false when arg type does not match required concrete type")
	}
}

// ── resolveOriginalType ───────────────────────────────────────────────────────

func TestResolveOriginalTypeDefault(t *testing.T) {
	t.Parallel()
	// A plain Const value — no ChangeInterface or MakeInterface wrapping.
	val := ssa.NewConst(constant.MakeString("test"), types.Typ[types.String])
	got := resolveOriginalType(val)
	if !types.Identical(got, types.Typ[types.String]) {
		t.Fatalf("expected string type, got %v", got)
	}
}

func TestAnalyzeSetsProgAndBuildsCallGraph(t *testing.T) {
	t.Parallel()

	// Build a minimal self-contained package with a local interface W.
	// Function f calls w.Write() which is configured as a sink below.
	src := `package p

type W interface{ Write([]byte) (int, error) }
type B struct{}

func (b *B) Write(p []byte) (int, error) { return 0, nil }
func f(w W)                               { w.Write([]byte("hello")) }
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, err := (&types.Config{}).Check("p", fset, []*ast.File{parsed}, info)
	if err != nil {
		t.Fatalf("type-check: %v", err)
	}
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	fn := ssaPkg.Func("f")
	if fn == nil {
		t.Fatal("SSA function f not found")
	}

	// Sink matches the invoke call w.Write inside f; ArgTypeGuards left empty
	// so guardsSatisfied is reached and returns true without further work.
	analyzer := New(&Config{
		Sinks: []Sink{
			{Package: "p", Receiver: "W", Method: "Write"},
		},
	})

	_ = analyzer.Analyze(prog, []*ssa.Function{fn})
}

func TestResolveOriginalTypeMakeInterface(t *testing.T) {
	t.Parallel()
	// Build a minimal, self-contained SSA program (no external imports) that
	// boxes a concrete *B value into interface W.  This exercises the
	// *ssa.MakeInterface branch of resolveOriginalType.
	src := `package p

type W interface{ Write([]byte) (int, error) }
type B struct{}

func (b *B) Write(p []byte) (int, error) { return 0, nil }
func f() W                               { return &B{} }
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, err := (&types.Config{}).Check("p", fset, []*ast.File{parsed}, info)
	if err != nil {
		t.Fatalf("type-check: %v", err)
	}
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	fn := ssaPkg.Func("f")
	if fn == nil {
		t.Fatal("SSA function f not found")
	}
	for _, blk := range fn.Blocks {
		for _, instr := range blk.Instrs {
			mi, ok := instr.(*ssa.MakeInterface)
			if !ok {
				continue
			}
			got := resolveOriginalType(mi)
			if got == nil {
				t.Fatal("resolveOriginalType returned nil for MakeInterface")
			}
			return
		}
	}
	t.Fatal("no MakeInterface instruction found in function f")
}
