package gosec

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/securego/gosec/v2/analyzers"
)

func BenchmarkTaintPackageAnalyzers_SharedCache(b *testing.B) {
	pkg := createTaintBenchmarkPackage(b, generateTaintStressProgram(180))

	logger := log.New(io.Discard, "", 0)
	analyzer := NewAnalyzer(NewConfig(), false, false, false, 6, logger)
	analyzer.LoadAnalyzers(analyzers.Generate(false,
		analyzers.NewAnalyzerFilter(false, "G701", "G702", "G703", "G704", "G705", "G706"),
	).AnalyzersInfo())

	ssaResult, err := analyzer.buildSSA(pkg)
	if err != nil {
		b.Fatalf("failed to build SSA: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		issues, stats := analyzer.checkAnalyzersWithSSA(pkg, ssaResult, nil)
		if stats == nil {
			b.Fatal("stats is nil")
		}
		if issues == nil {
			b.Fatal("issues slice is nil")
		}
	}
}

func createTaintBenchmarkPackage(b *testing.B, source string) *packages.Package {
	b.Helper()

	tmpDir, err := os.MkdirTemp("", "gosec_taint_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	mainGo := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainGo, []byte(source), 0o600); err != nil {
		b.Fatalf("failed to write source file: %v", err)
	}

	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte("module bench\n\ngo 1.25\n"), 0o600); err != nil {
		b.Fatalf("failed to write go.mod: %v", err)
	}

	conf := &packages.Config{
		Mode: LoadMode,
		Dir:  tmpDir,
	}

	pkgs, err := packages.Load(conf, ".")
	if err != nil {
		b.Fatalf("failed to load package: %v", err)
	}
	if len(pkgs) == 0 {
		b.Fatal("no packages loaded")
	}
	if len(pkgs[0].Errors) > 0 {
		b.Fatalf("errors loading package: %v", pkgs[0].Errors)
	}

	return pkgs[0]
}

func generateTaintStressProgram(functionCount int) string {
	var sb strings.Builder

	sb.WriteString("package main\n")
	sb.WriteString("\nimport (\n")
	sb.WriteString("\t\"database/sql\"\n")
	sb.WriteString("\t\"fmt\"\n")
	sb.WriteString("\t\"log\"\n")
	sb.WriteString("\t\"net/http\"\n")
	sb.WriteString("\t\"os\"\n")
	sb.WriteString("\t\"os/exec\"\n")
	sb.WriteString(")\n\n")

	sb.WriteString("var globalDB *sql.DB\n\n")

	for i := range functionCount {
		fmt.Fprintf(&sb, "func sinkFanout%d(w http.ResponseWriter, r *http.Request) {\n", i)
		sb.WriteString("\tq := r.URL.Query().Get(\"q\")\n")
		sb.WriteString("\tenv := os.Getenv(\"TAINT_ENV\")\n")
		sb.WriteString("\tjoined := q + env\n")
		sb.WriteString("\t_, _ = globalDB.Query(joined)\n")
		sb.WriteString("\t_ = exec.Command(\"sh\", \"-c\", joined)\n")
		sb.WriteString("\t_, _ = os.Open(joined)\n")
		sb.WriteString("\t_, _ = http.Get(joined)\n")
		sb.WriteString("\t_, _ = fmt.Fprintf(w, \"%s\", joined)\n")
		sb.WriteString("\t_, _ = w.Write([]byte(joined))\n")
		sb.WriteString("\tlog.Print(joined)\n")
		sb.WriteString("}\n\n")
	}

	sb.WriteString("func main() {\n")
	sb.WriteString("\thttp.HandleFunc(\"/\", func(w http.ResponseWriter, r *http.Request) {\n")
	for i := range functionCount {
		fmt.Fprintf(&sb, "\t\tsinkFanout%d(w, r)\n", i)
	}
	sb.WriteString("\t})\n")
	sb.WriteString("}\n")

	return sb.String()
}
