package taint

import (
	"go/token"
	"testing"

	"golang.org/x/tools/go/ssa"
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
