package taint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

func TestRunnerSinkParity(t *testing.T) {
	const source = `package p
func Source() string { return "" }
func Sink(string) {}
func Other(string) {}
type Writer interface { Write(string) }
type Output struct{}
func (*Output) Write(string) {}
func Sinkless() { Other(Source()) }
func Direct() { Sink(Source()) }
func Forward(value string) { Sink(value) }
func Indirect() { Forward(Source()) }
func Concrete(output *Output) { output.Write(Source()) }
func Dynamic(output Writer) { output.Write(Source()) }
func Closure() { f := func() { Sink(Source()) }; f() }
func Constant() { Sink("safe") }
`
	tests := []struct {
		name   string
		target string
		sink   Sink
		want   int
	}{
		{name: "no sink", target: "Sinkless", sink: Sink{Package: "p", Method: "Sink"}},
		{name: "direct", target: "Direct", sink: Sink{Package: "p", Method: "Sink"}, want: 1},
		{name: "caller flow", target: "Forward", sink: Sink{Package: "p", Method: "Sink"}, want: 1},
		{name: "concrete method", target: "Concrete", sink: Sink{Package: "p", Receiver: "Output", Method: "Write", Pointer: true, CheckArgs: []int{1}}, want: 1},
		{name: "interface", target: "Dynamic", sink: Sink{Package: "p", Receiver: "Writer", Method: "Write"}, want: 1},
		{name: "closure", target: "Closure", sink: Sink{Package: "p", Method: "Sink"}, want: 1},
		{name: "constant", target: "Constant", sink: Sink{Package: "p", Method: "Sink"}},
		{name: "different package", target: "Direct", sink: Sink{Package: "other", Method: "Sink"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Sources: []Source{{Package: "p", Name: "Source", IsFunc: true}},
				Sinks:   []Sink{tt.sink},
			}
			_, result := sinkPrecheckPass(t, source, tt.target)
			baseline := New(cfg)
			baseline.SetCallGraph(cha.CallGraph(result.Pkg.Prog))
			expected := baseline.Analyze(result.Pkg.Prog, result.SrcFuncs)
			require.Len(t, expected, tt.want)

			for _, shared := range []bool{false, true} {
				pass, result := sinkPrecheckPass(t, source, tt.target)
				input := &ssautil.SSAAnalyzerResult{SSA: result}
				if shared {
					input.Shared = ssautil.NewPackageAnalysisCache(result)
				}
				pass.ResultOf[buildssa.Analyzer] = input
				var reported []analysis.Diagnostic
				pass.Report = func(d analysis.Diagnostic) { reported = append(reported, d) }

				runner := NewGosecAnalyzer(&RuleInfo{ID: "G701", Description: "test sink", Severity: "HIGH"}, cfg)
				value, err := runner.Run(pass)
				require.NoError(t, err)
				assert.Len(t, reported, tt.want)
				if tt.want == 0 {
					assert.Nil(t, value)
					continue
				}
				issues, ok := value.([]*issue.Issue)
				require.True(t, ok)
				require.Len(t, issues, tt.want)
				for i, found := range issues {
					assert.Equal(t, expected[i].SinkPos, reported[i].Pos)
					assert.Equal(t, fmt.Sprint(pass.Fset.Position(expected[i].SinkPos).Line), found.Line)
				}
			}
		})
	}
}

func TestRunnerWithoutSinksDoesNotBuildCallGraph(t *testing.T) {
	pass, result := sinkPrecheckPass(t, "package p\nfunc F() {}\n", "F")
	// A nil Prog makes any call graph build panic.
	result.SrcFuncs[0].Prog = nil
	pass.ResultOf[buildssa.Analyzer] = &ssautil.SSAAnalyzerResult{
		SSA: result, Shared: ssautil.NewPackageAnalysisCache(result),
	}
	runner := NewGosecAnalyzer(&RuleInfo{ID: "G701", Severity: "HIGH"}, &Config{
		Sinks: []Sink{{Package: "p", Method: "Sink"}},
	})

	value, err := runner.Run(pass)
	require.NoError(t, err)
	assert.Nil(t, value)
}

func BenchmarkRunnerWithoutSinks(b *testing.B) {
	for _, count := range []int{1, 32, 256} {
		b.Run(fmt.Sprintf("types=%d", count), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("package p\nfunc F() {}\n")
			for i := range count {
				fmt.Fprintf(&source, "type T%d struct{}\nfunc (T%d) M() {}\n", i, i)
			}
			pass, result := sinkPrecheckPass(b, source.String(), "F")
			runner := NewGosecAnalyzer(&RuleInfo{ID: "G701", Description: "test sink", Severity: "HIGH"}, &Config{
				Sinks: []Sink{{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true}},
			})
			b.ReportAllocs()
			for b.Loop() {
				pass.ResultOf[buildssa.Analyzer] = &ssautil.SSAAnalyzerResult{
					SSA: result, Shared: ssautil.NewPackageAnalysisCache(result),
				}
				value, err := runner.Run(pass)
				require.NoError(b, err)
				require.Nil(b, value)
			}
		})
	}
}

func sinkPrecheckPass(tb testing.TB, source, target string) (*analysis.Pass, *buildssa.SSA) {
	tb.Helper()
	filename := filepath.Join(tb.TempDir(), "p.go")
	require.NoError(tb, os.WriteFile(filename, []byte(source), 0o600))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, source, 0)
	require.NoError(tb, err)
	files := []*ast.File{file}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Implicits: make(map[ast.Node]types.Object),
		Scopes: make(map[ast.Node]*types.Scope), Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances: make(map[*ast.Ident]types.Instance),
	}
	var cfg types.Config
	pkg, err := cfg.Check("p", fset, files, info)
	require.NoError(tb, err)
	prog := ssa.NewProgram(fset, 0)
	ssaPkg := prog.CreatePackage(pkg, files, info, true)
	ssaPkg.Build()
	fn := ssaPkg.Func(target)
	require.NotNil(tb, fn)
	funcs := []*ssa.Function{fn}
	funcs = append(funcs, fn.AnonFuncs...)
	pass := &analysis.Pass{
		Fset: fset, Files: files, Pkg: pkg, TypesInfo: info,
		ResultOf: make(map[*analysis.Analyzer]any), Report: func(analysis.Diagnostic) {},
	}
	return pass, &buildssa.SSA{Pkg: ssaPkg, SrcFuncs: funcs}
}
