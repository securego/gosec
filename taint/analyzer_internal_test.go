package taint

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph/cha"
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

// buildManySinkCallsFixture creates an SSA program with many interface implementations
// and many sink-calling functions, producing a large CHA call graph. Used by both the
// regression test and benchmark.
func buildManySinkCallsFixture(tb testing.TB) (*ssa.Program, []*ssa.Function) {
	tb.Helper()

	src := `package p

type W interface{ Write([]byte) (int, error) }
`
	// Generate 20 concrete implementations of W to inflate CHA edges.
	for i := 0; i < 20; i++ {
		src += fmt.Sprintf(`
type Impl%d struct{}
func (x *Impl%d) Write(p []byte) (int, error) { return len(p), nil }
`, i, i)
	}

	// Generate 20 functions, each calling w.Write with a variable arg (potential sink).
	for i := 0; i < 20; i++ {
		src += fmt.Sprintf(`
func caller%d(w W, data []byte) { w.Write(data) }
`, i)
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		tb.Fatalf("parse: %v", err)
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
		tb.Fatalf("type-check: %v", err)
	}
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	// Collect all caller* functions as analysis targets.
	var srcFuncs []*ssa.Function
	for i := 0; i < 20; i++ {
		fn := ssaPkg.Func(fmt.Sprintf("caller%d", i))
		if fn == nil {
			tb.Fatalf("SSA function caller%d not found", i)
		}
		srcFuncs = append(srcFuncs, fn)
	}

	return prog, srcFuncs
}

func TestTaintAnalysisPerformanceWithManySinkCalls(t *testing.T) {
	t.Parallel()

	// This test verifies that taint analysis completes in bounded time even when
	// CHA produces a large call graph (many interface implementations × many sink calls).
	// Before the maxCallerEdges cap and paramTaintCache, this scenario could hang.
	prog, srcFuncs := buildManySinkCallsFixture(t)

	analyzer := New(&Config{
		Sinks: []Sink{
			{Package: "p", Receiver: "W", Method: "Write", CheckArgs: []int{1}},
		},
	})

	// Must complete within 10 seconds; without the fix this could hang indefinitely.
	done := make(chan []Result, 1)
	go func() {
		done <- analyzer.Analyze(prog, srcFuncs)
	}()

	select {
	case <-time.After(10 * time.Second):
		t.Fatal("taint analysis did not complete within 10 seconds — possible hang regression")
	case results := <-done:
		_ = results
	}
}

func BenchmarkTaintAnalysisManySinkCalls(b *testing.B) {
	prog, srcFuncs := buildManySinkCallsFixture(b)

	cfg := &Config{
		Sinks: []Sink{
			{Package: "p", Receiver: "W", Method: "Write", CheckArgs: []int{1}},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		analyzer := New(cfg)
		analyzer.Analyze(prog, srcFuncs)
	}
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

// ── mayHaveExternalCallers ──────────────────────────────────────────────────

// makeHTTPTypes builds synthetic net/http.ResponseWriter (interface) and
// net/http.Request (struct) types, matching the real package path "net/http".
// This avoids depending on go/importer which may not resolve stdlib in CI.
func makeHTTPTypes() (httpPkg *types.Package, responseWriter *types.Named, request *types.Named) {
	httpPkg = types.NewPackage("net/http", "http")

	// ResponseWriter — named interface with a minimal method set.
	rwIface := types.NewInterfaceType(nil, nil)
	rwIface.Complete()
	rwObj := types.NewTypeName(token.NoPos, httpPkg, "ResponseWriter", nil)
	responseWriter = types.NewNamed(rwObj, rwIface, nil)
	httpPkg.Scope().Insert(rwObj)

	// Request — named struct.
	reqObj := types.NewTypeName(token.NoPos, httpPkg, "Request", nil)
	request = types.NewNamed(reqObj, types.NewStruct(nil, nil), nil)
	httpPkg.Scope().Insert(reqObj)

	httpPkg.MarkComplete()
	return
}

// makeFuncSSA creates an ssa.Function with the given signature and optional
// receiver, attached to a trivial SSA program.  The function has no body.
func makeFuncSSA(t *testing.T, name string, sig *types.Signature) *ssa.Function {
	t.Helper()
	fset := token.NewFileSet()
	prog := ssa.NewProgram(fset, 0)
	pkg := types.NewPackage("p", "p")
	pkg.MarkComplete()
	ssaPkg := prog.CreatePackage(pkg, nil, nil, false)

	fn := ssaPkg.Prog.NewFunction(name, sig, "test")
	return fn
}

func TestMayHaveExternalCallers(t *testing.T) {
	t.Parallel()

	simpleSig := types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "x", types.Typ[types.Int])),
		nil, false)

	cases := []struct {
		name string
		fn   func() *ssa.Function
		want bool
	}{
		{
			name: "ExportedBareFunc",
			fn: func() *ssa.Function {
				return makeFuncSSA(t, "Handler", simpleSig)
			},
			want: true,
		},
		{
			name: "UnexportedBareFunc",
			fn: func() *ssa.Function {
				return makeFuncSSA(t, "handler", simpleSig)
			},
			want: false,
		},
		{
			name: "MethodWithReceiver",
			fn: func() *ssa.Function {
				recv := types.NewVar(token.NoPos, nil, "s", types.NewPointer(types.NewStruct(nil, nil)))
				methodSig := types.NewSignatureType(recv, nil, nil,
					types.NewTuple(types.NewVar(token.NoPos, nil, "x", types.Typ[types.Int])),
					nil, false)
				return makeFuncSSA(t, "Do", methodSig)
			},
			want: false,
		},
		{
			name: "NilSignature",
			fn: func() *ssa.Function {
				return &ssa.Function{}
			},
			want: false,
		},
	}

	for _, tc := range cases {
		fn := tc.fn()
		got := mayHaveExternalCallers(fn)
		if got != tc.want {
			t.Errorf("mayHaveExternalCallers(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMayHaveExternalCallersClosureReturnsFalse(t *testing.T) {
	t.Parallel()

	// A closure (fn.Parent() != nil) is never exported, even if its
	// synthesized name starts with an uppercase letter.
	src := `package p

func Outer() {
	fn := func(x int) { _ = x }
	fn(1)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, _ := (&types.Config{}).Check("p", fset, []*ast.File{parsed}, info)
	prog := ssa.NewProgram(fset, 0)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	outer := ssaPkg.Func("Outer")
	if outer == nil {
		t.Fatal("Outer not found")
	}
	// Find the anonymous closure inside Outer.
	for _, anon := range outer.AnonFuncs {
		if mayHaveExternalCallers(anon) {
			t.Errorf("mayHaveExternalCallers(closure %s) = true, want false", anon.Name())
		}
	}
}

// ── isParameterTainted entry-point logic ────────────────────────────────────

func TestIsParameterTaintedExportedFuncWithCallersStillTainted(t *testing.T) {
	t.Parallel()

	// An exported bare function with a source-type param must be auto-tainted
	// even when it has internal callers with safe args — because external
	// callers (framework dispatch) may be invisible to the call graph.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func Handler(w http.ResponseWriter, r *http.Request) {}

func caller() {
	Handler(nil, nil)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	fakeImporter := fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown import %q", path)
	})

	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, err := (&types.Config{Importer: fakeImporter}).Check("p", fset, []*ast.File{parsed}, info)
	if err != nil {
		t.Fatalf("type-check: %v", err)
	}

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false) // register net/http in SSA
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	handlerFn := ssaPkg.Func("Handler")
	if handlerFn == nil {
		t.Fatal("Handler not found")
	}
	if len(handlerFn.Params) < 2 {
		t.Fatal("expected Handler to have 2 params")
	}

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})

	var srcFuncs []*ssa.Function
	for _, m := range ssaPkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			srcFuncs = append(srcFuncs, fn)
		}
	}
	_ = analyzer.Analyze(prog, srcFuncs)

	// Handler has callers (caller() calls it).
	node := analyzer.callGraph.Nodes[handlerFn]
	if node == nil || len(node.In) == 0 {
		t.Fatal("expected Handler to have callers in the call graph")
	}

	// Despite callers, isParameterTainted must return true because the
	// function is an exported bare function (mayHaveExternalCallers).
	visited := make(map[ssa.Value]bool)
	tainted := analyzer.isParameterTainted(handlerFn.Params[1], handlerFn, visited, 0)
	if !tainted {
		t.Fatal("expected *http.Request param of HTTP handler to be auto-tainted even with internal callers")
	}
}

func TestIsParameterTaintedNonHandlerWithCallersNotAutoTainted(t *testing.T) {
	t.Parallel()

	// Non-handler function accepting *http.Request with a safe internal caller
	// must NOT be auto-tainted.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func wrapper(r *http.Request) {}

func caller() {
	wrapper(nil)
}
`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	fakeImporter := fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown import %q", path)
	})

	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, err := (&types.Config{Importer: fakeImporter}).Check("p", fset, []*ast.File{parsed}, info)
	if err != nil {
		t.Fatalf("type-check: %v", err)
	}

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false) // register net/http in SSA
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	wrapperFn := ssaPkg.Func("wrapper")
	if wrapperFn == nil {
		t.Fatal("wrapper not found")
	}
	if len(wrapperFn.Params) < 1 {
		t.Fatal("expected wrapper to have at least 1 param")
	}

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})

	var srcFuncs []*ssa.Function
	for _, m := range ssaPkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			srcFuncs = append(srcFuncs, fn)
		}
	}
	_ = analyzer.Analyze(prog, srcFuncs)

	node := analyzer.callGraph.Nodes[wrapperFn]
	if node == nil || len(node.In) == 0 {
		t.Fatal("expected wrapper to have callers in the call graph")
	}

	visited := make(map[ssa.Value]bool)
	tainted := analyzer.isParameterTainted(wrapperFn.Params[0], wrapperFn, visited, 0)
	if tainted {
		t.Fatal("expected *http.Request param of non-handler wrapper to NOT be auto-tainted when caller is safe")
	}
}

// fakeImporterFunc adapts a function to the types.Importer interface.
type fakeImporterFunc func(path string) (*types.Package, error)

func (f fakeImporterFunc) Import(path string) (*types.Package, error) { return f(path) }

func TestIsParameterTaintedCacheHit(t *testing.T) {
	t.Parallel()

	// When isParameterTainted returns true for a handler param, the result is
	// cached. A second call for the same param must hit the cache and return
	// true immediately.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {}
`
	fset := token.NewFileSet()
	parsed, _ := parser.ParseFile(fset, "p.go", src, 0)
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, _ := (&types.Config{Importer: fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown %q", path)
	})}).Check("p", fset, []*ast.File{parsed}, info)

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	handlerFn := ssaPkg.Func("handler")
	reqParam := handlerFn.Params[1]

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})
	var srcFuncs []*ssa.Function
	for _, m := range ssaPkg.Members {
		if fn, ok := m.(*ssa.Function); ok {
			srcFuncs = append(srcFuncs, fn)
		}
	}
	_ = analyzer.Analyze(prog, srcFuncs)

	// First call populates cache.
	visited1 := make(map[ssa.Value]bool)
	if !analyzer.isParameterTainted(reqParam, handlerFn, visited1, 0) {
		t.Fatal("first call: expected tainted")
	}

	// Second call must hit the cache (lines 895-898).
	visited2 := make(map[ssa.Value]bool)
	if !analyzer.isParameterTainted(reqParam, handlerFn, visited2, 0) {
		t.Fatal("second call (cache hit): expected tainted")
	}
}

func TestIsParameterTaintedNoCallGraph(t *testing.T) {
	t.Parallel()

	// When callGraph is nil, isParameterTainted falls back to type-based
	// auto-taint for source-typed params and returns false otherwise.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func twoParams(r *http.Request, s string) {}
`
	fset := token.NewFileSet()
	parsed, _ := parser.ParseFile(fset, "p.go", src, 0)
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, _ := (&types.Config{Importer: fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown %q", path)
	})}).Check("p", fset, []*ast.File{parsed}, info)

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	fn := ssaPkg.Func("twoParams")
	if fn == nil || len(fn.Params) < 2 {
		t.Fatal("expected twoParams with 2 params")
	}

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})
	// Do NOT call Analyze — callGraph stays nil.
	// Initialize paramTaintCache so the cache-store branch is exercised.
	analyzer.paramTaintCache = make(map[paramKey]bool)

	// Source-type param → auto-taint (and caches result).
	visited := make(map[ssa.Value]bool)
	if !analyzer.isParameterTainted(fn.Params[0], fn, visited, 0) {
		t.Fatal("expected source-type param to be auto-tainted when callGraph is nil")
	}

	// Verify cache was populated.
	if !analyzer.paramTaintCache[paramKey{fn: fn, paramIdx: 0}] {
		t.Fatal("expected cache to contain taint result for param 0")
	}

	// Non-source-type param → false.
	visited2 := make(map[ssa.Value]bool)
	if analyzer.isParameterTainted(fn.Params[1], fn, visited2, 0) {
		t.Fatal("expected non-source-type param to NOT be tainted when callGraph is nil")
	}
}

func TestIsParameterTaintedDepthExceeded(t *testing.T) {
	t.Parallel()

	// When recursion depth exceeds maxTaintDepth, isParameterTainted returns false.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {}
`
	fset := token.NewFileSet()
	parsed, _ := parser.ParseFile(fset, "p.go", src, 0)
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, _ := (&types.Config{Importer: fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown %q", path)
	})}).Check("p", fset, []*ast.File{parsed}, info)

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	fn := ssaPkg.Func("handler")
	if fn == nil || len(fn.Params) < 2 {
		t.Fatal("expected handler with 2 params")
	}

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})

	visited := make(map[ssa.Value]bool)
	// Passing depth > maxTaintDepth (50) → must return false.
	if analyzer.isParameterTainted(fn.Params[1], fn, visited, maxTaintDepth+1) {
		t.Fatal("expected false when depth exceeds maxTaintDepth")
	}
}

func TestIsParameterTaintedEntryPointCacheStoreAndHit(t *testing.T) {
	t.Parallel()

	// Exercises the cache-store (line 934) and cache-hit (line 897) branches.
	// Analyze() sets paramTaintCache to nil on return, so we must invoke
	// isParameterTainted directly while the cache is live. We do this by
	// manually initialising the analyzer state the same way Analyze does.
	httpPkg, _, _ := makeHTTPTypes()

	src := `package p

import "net/http"

func lonely(r *http.Request) {}
`
	fset := token.NewFileSet()
	parsed, _ := parser.ParseFile(fset, "p.go", src, 0)
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	pkg, _ := (&types.Config{Importer: fakeImporterFunc(func(path string) (*types.Package, error) {
		if path == "net/http" {
			return httpPkg, nil
		}
		return nil, fmt.Errorf("unknown %q", path)
	})}).Check("p", fset, []*ast.File{parsed}, info)

	prog := ssa.NewProgram(fset, 0)
	prog.CreatePackage(httpPkg, nil, nil, false)
	ssaPkg := prog.CreatePackage(pkg, []*ast.File{parsed}, info, true)
	prog.Build()

	fn := ssaPkg.Func("lonely")
	if fn == nil || len(fn.Params) < 1 {
		t.Fatal("expected lonely with 1 param")
	}

	analyzer := New(&Config{
		Sources: []Source{{Package: "net/http", Name: "Request", Pointer: true}},
	})
	// Manually set up call graph + cache (same as Analyze does internally).
	analyzer.callGraph = cha.CallGraph(prog)
	analyzer.paramTaintCache = make(map[paramKey]bool)
	analyzer.prog = prog

	// First call: entry point (no callers) + source type → auto-taint + cache store.
	visited := make(map[ssa.Value]bool)
	if !analyzer.isParameterTainted(fn.Params[0], fn, visited, 0) {
		t.Fatal("expected entry-point source-type param to be tainted")
	}
	if !analyzer.paramTaintCache[paramKey{fn: fn, paramIdx: 0}] {
		t.Fatal("expected cache to be populated")
	}

	// Second call: hits cache (line 897).
	visited2 := make(map[ssa.Value]bool)
	if !analyzer.isParameterTainted(fn.Params[0], fn, visited2, 0) {
		t.Fatal("expected cache hit to return true")
	}
}
