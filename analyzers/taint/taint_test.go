package taint

import (
	"go/token"
	"os"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// TestFormatSinkKey tests the sink key formatting.
func TestFormatSinkKey(t *testing.T) {
	tests := []struct {
		sink Sink
		want string
	}{
		{
			sink: Sink{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
			want: "(*database/sql.DB).Query",
		},
		{
			sink: Sink{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: false},
			want: "(database/sql.DB).Query",
		},
		{
			sink: Sink{Package: "os/exec", Method: "Command"},
			want: "os/exec.Command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatSinkKey(tt.sink)
			if got != tt.want {
				t.Errorf("formatSinkKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConfigMerge tests merging multiple configurations.
func TestConfigMerge(t *testing.T) {
	config1 := SQLInjection()
	config2 := CommandInjection()

	// Merge configs
	merged := Config{
		Sources: append(config1.Sources, config2.Sources...),
		Sinks:   append(config1.Sinks, config2.Sinks...),
	}

	if len(merged.Sources) != len(config1.Sources)+len(config2.Sources) {
		t.Errorf("merged sources count mismatch")
	}

	if len(merged.Sinks) != len(config1.Sinks)+len(config2.Sinks) {
		t.Errorf("merged sinks count mismatch")
	}
}

// TestAllConfigs tests that all predefined configs are valid.
func TestAllConfigs(t *testing.T) {
	configs := AllConfigs()

	expectedConfigs := []string{
		"sql_injection",
		"command_injection",
		"path_traversal",
		"ssrf",
		"xss",
		"log_injection",
	}

	for _, name := range expectedConfigs {
		config, ok := configs[name]
		if !ok {
			t.Errorf("missing config: %s", name)
			continue
		}

		if len(config.Sources) == 0 {
			t.Errorf("config %s has no sources", name)
		}

		if len(config.Sinks) == 0 {
			t.Errorf("config %s has no sinks", name)
		}

		// Validate sources
		for i, src := range config.Sources {
			if src.Package == "" {
				t.Errorf("config %s source[%d] has empty package", name, i)
			}
			if src.Name == "" {
				t.Errorf("config %s source[%d] has empty name", name, i)
			}
		}

		// Validate sinks
		for i, sink := range config.Sinks {
			if sink.Package == "" {
				t.Errorf("config %s sink[%d] has empty package", name, i)
			}
			if sink.Method == "" {
				t.Errorf("config %s sink[%d] has empty method", name, i)
			}
		}
	}
}

// TestNew tests the analyzer constructor.
// TestSourceType tests Source type structure.
func TestSourceType(t *testing.T) {
	tests := []struct {
		name    string
		source  Source
		wantKey string
	}{
		{
			name:    "pointer_type",
			source:  Source{Package: "net/http", Name: "Request", Pointer: true},
			wantKey: "*net/http.Request",
		},
		{
			name:    "non_pointer_type",
			source:  Source{Package: "os", Name: "Args", Pointer: false},
			wantKey: "os.Args",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Sources: []Source{tt.source}}
			analyzer := New(config)

			if _, ok := analyzer.sources[tt.wantKey]; !ok {
				t.Errorf("source key %q not found in analyzer.sources", tt.wantKey)
			}
		})
	}
}

// TestSinkType tests Sink type structure.
func TestSinkType(t *testing.T) {
	tests := []struct {
		name    string
		sink    Sink
		wantKey string
	}{
		{
			name:    "method_with_pointer_receiver",
			sink:    Sink{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
			wantKey: "(*database/sql.DB).Query",
		},
		{
			name:    "method_with_value_receiver",
			sink:    Sink{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: false},
			wantKey: "(database/sql.DB).Query",
		},
		{
			name:    "package_function",
			sink:    Sink{Package: "os/exec", Method: "Command"},
			wantKey: "os/exec.Command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Sinks: []Sink{tt.sink}}
			analyzer := New(config)

			// Check the key exists in the sinks map
			found := false
			for key := range analyzer.sinks {
				if key == tt.wantKey {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("sink key %q not found in analyzer.sinks", tt.wantKey)
			}
		})
	}
}

// TestResult tests Result type structure.
// TestAnalyzerWithNilFunction tests handling of nil functions.
func TestAnalyzerWithNilFunction(t *testing.T) {
	config := SQLInjection()
	analyzer := New(&config)

	prog := ssa.NewProgram(token.NewFileSet(), ssa.SanityCheckFunctions)
	results := analyzer.Analyze(prog, []*ssa.Function{nil})

	if len(results) != 0 {
		t.Errorf("expected 0 results for nil function, got %d", len(results))
	}
}

// TestFormatSinkKeyVariations tests various sink key formats.
// TestConfigValidation tests config validation.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid_config",
			config: Config{
				Sources: []Source{{Package: "net/http", Name: "Request"}},
				Sinks:   []Sink{{Package: "database/sql", Method: "Query"}},
			},
			valid: true,
		},
		{
			name: "empty_sources",
			config: Config{
				Sources: []Source{},
				Sinks:   []Sink{{Package: "pkg", Method: "Method"}},
			},
			valid: true, // Empty sources is valid
		},
		{
			name: "empty_sinks",
			config: Config{
				Sources: []Source{{Package: "pkg", Name: "Type"}},
				Sinks:   []Sink{},
			},
			valid: true, // Empty sinks is valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := New(&tt.config)
			if analyzer == nil && tt.valid {
				t.Error("expected valid analyzer, got nil")
			}
		})
	}
}

// TestMultipleSourcesAndSinks tests analyzer with multiple sources and sinks.
func TestMultipleSourcesAndSinks(t *testing.T) {
	config := &Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "bufio", Name: "Reader", Pointer: true},
		},
		Sinks: []Sink{
			{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
			{Package: "os/exec", Method: "Command"},
			{Package: "fmt", Method: "Printf"},
		},
	}

	analyzer := New(config)

	if len(analyzer.sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(analyzer.sources))
	}

	if len(analyzer.sinks) != 3 {
		t.Errorf("expected 3 sinks, got %d", len(analyzer.sinks))
	}
}

// TestSourceKeyFormats tests various source key formats.
func TestSourceKeyFormats(t *testing.T) {
	tests := []struct {
		name    string
		source  Source
		wantKey string
	}{
		{
			name:    "simple_type",
			source:  Source{Package: "pkg", Name: "Type"},
			wantKey: "pkg.Type",
		},
		{
			name:    "pointer_type",
			source:  Source{Package: "pkg", Name: "Type", Pointer: true},
			wantKey: "*pkg.Type",
		},
		{
			name:    "nested_package",
			source:  Source{Package: "parent/child", Name: "Type"},
			wantKey: "parent/child.Type",
		},
		{
			name:    "function",
			source:  Source{Package: "pkg", Name: "Function"},
			wantKey: "pkg.Function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{Sources: []Source{tt.source}}
			analyzer := New(config)

			if _, ok := analyzer.sources[tt.wantKey]; !ok {
				t.Errorf("expected source key %q not found", tt.wantKey)
			}
		})
	}
}

// TestAnalyzerCallGraphNil tests analyzer behavior with nil call graph.
func TestAnalyzerCallGraphNil(t *testing.T) {
	config := SQLInjection()
	analyzer := New(&config)

	// Call graph should be nil until Analyze is called
	if analyzer.callGraph != nil {
		t.Error("callGraph should be nil before Analyze is called")
	}
}

// TestEmptyPath tests Result with empty path.
// TestSinkWithoutReceiver tests sink without receiver (package function).
func TestSinkWithoutReceiver(t *testing.T) {
	sink := Sink{
		Package: "os/exec",
		Method:  "Command",
	}

	if sink.Receiver != "" {
		t.Errorf("expected empty receiver, got %q", sink.Receiver)
	}

	key := formatSinkKey(sink)
	expectedKey := "os/exec.Command"
	if key != expectedKey {
		t.Errorf("formatSinkKey() = %q, want %q", key, expectedKey)
	}
}

// TestSourcePointerVariations tests pointer vs non-pointer sources.
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

// TestAnalyzeRealSQLInjection tests detection with real Go code
func TestAnalyzeRealSQLInjection(t *testing.T) {
	src := `package main
import ("database/sql"; "net/http")
func handler(db *sql.DB, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}`

	prog, funcs := buildSSA(t, src)
	config := SQLInjection()
	analyzer := New(&config)
	results := analyzer.Analyze(prog, funcs)

	if len(results) == 0 {
		t.Error("expected SQL injection detection")
	}
}

// TestAnalyzeRealPathTraversal tests path traversal detection
func TestAnalyzeRealPathTraversal(t *testing.T) {
	src := `package main
import ("net/http"; "os")
func handler(r *http.Request) {
	path := r.URL.Query().Get("file")
	os.Open(path)
}`

	prog, funcs := buildSSA(t, src)
	config := PathTraversal()
	analyzer := New(&config)
	results := analyzer.Analyze(prog, funcs)

	if len(results) == 0 {
		t.Error("expected path traversal detection")
	}
}

// TestAnalyzeSafeCode tests that safe code doesn't trigger false positives
func TestAnalyzeSafeCode(t *testing.T) {
	src := `package main
import "database/sql"
func handler(db *sql.DB) {
	db.Query("SELECT * FROM users")
}`

	prog, funcs := buildSSA(t, src)
	config := SQLInjection()
	analyzer := New(&config)
	results := analyzer.Analyze(prog, funcs)

	if len(results) != 0 {
		t.Error("unexpected false positive")
	}
}
