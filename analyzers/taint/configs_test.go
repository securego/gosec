package taint

import (
	"testing"
)

// TestSQLInjectionConfig tests the SQL injection configuration.
func TestSQLInjectionConfig(t *testing.T) {
	config := SQLInjection()

	if len(config.Sources) == 0 {
		t.Error("SQLInjection config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("SQLInjection config has no sinks")
	}

	// Check for expected sources
	hasHTTPRequest := false
	for _, src := range config.Sources {
		if src.Package == "net/http" && src.Name == "Request" {
			hasHTTPRequest = true
		}
	}
	if !hasHTTPRequest {
		t.Error("SQLInjection config missing net/http.Request source")
	}

	// Check for expected sinks
	hasDBQuery := false
	for _, sink := range config.Sinks {
		if sink.Package == "database/sql" && sink.Receiver == "DB" && sink.Method == "Query" {
			hasDBQuery = true
		}
	}
	if !hasDBQuery {
		t.Error("SQLInjection config missing database/sql.DB.Query sink")
	}
}

// TestCommandInjectionConfig tests the command injection configuration.
func TestCommandInjectionConfig(t *testing.T) {
	config := CommandInjection()

	if len(config.Sources) == 0 {
		t.Error("CommandInjection config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("CommandInjection config has no sinks")
	}

	// Check for expected sinks
	hasExecCommand := false
	for _, sink := range config.Sinks {
		if sink.Package == "os/exec" && sink.Method == "Command" {
			hasExecCommand = true
		}
	}
	if !hasExecCommand {
		t.Error("CommandInjection config missing os/exec.Command sink")
	}
}

// TestPathTraversalConfig tests the path traversal configuration.
func TestPathTraversalConfig(t *testing.T) {
	config := PathTraversal()

	if len(config.Sources) == 0 {
		t.Error("PathTraversal config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("PathTraversal config has no sinks")
	}

	// Check for expected sinks
	hasOsOpen := false
	for _, sink := range config.Sinks {
		if sink.Package == "os" && sink.Method == "Open" {
			hasOsOpen = true
		}
	}
	if !hasOsOpen {
		t.Error("PathTraversal config missing os.Open sink")
	}
}

// TestSSRFConfig tests the SSRF configuration.
func TestSSRFConfig(t *testing.T) {
	config := SSRF()

	if len(config.Sources) == 0 {
		t.Error("SSRF config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("SSRF config has no sinks")
	}

	// Check for expected sinks
	hasHTTPGet := false
	for _, sink := range config.Sinks {
		if sink.Package == "net/http" && sink.Method == "Get" {
			hasHTTPGet = true
		}
	}
	if !hasHTTPGet {
		t.Error("SSRF config missing net/http.Get sink")
	}
}

// TestXSSConfig tests the XSS configuration.
func TestXSSConfig(t *testing.T) {
	config := XSS()

	if len(config.Sources) == 0 {
		t.Error("XSS config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("XSS config has no sinks")
	}

	// Check for expected sinks
	hasResponseWrite := false
	for _, sink := range config.Sinks {
		if sink.Package == "net/http" && sink.Receiver == "ResponseWriter" && sink.Method == "Write" {
			hasResponseWrite = true
		}
	}
	if !hasResponseWrite {
		t.Error("XSS config missing net/http.ResponseWriter.Write sink")
	}
}

// TestLogInjectionConfig tests the log injection configuration.
func TestLogInjectionConfig(t *testing.T) {
	config := LogInjection()

	if len(config.Sources) == 0 {
		t.Error("LogInjection config has no sources")
	}

	if len(config.Sinks) == 0 {
		t.Error("LogInjection config has no sinks")
	}

	// Check for expected sinks
	hasLogPrint := false
	for _, sink := range config.Sinks {
		if sink.Package == "log" && sink.Method == "Print" {
			hasLogPrint = true
		}
	}
	if !hasLogPrint {
		t.Error("LogInjection config missing log.Print sink")
	}
}

// TestAllConfigsCompleteness tests that AllConfigs returns all configs.
func TestAllConfigsCompleteness(t *testing.T) {
	configs := AllConfigs()

	expectedConfigs := []string{
		"sql_injection",
		"command_injection",
		"path_traversal",
		"ssrf",
		"xss",
		"log_injection",
	}

	if len(configs) != len(expectedConfigs) {
		t.Errorf("expected %d configs, got %d", len(expectedConfigs), len(configs))
	}

	for _, name := range expectedConfigs {
		if _, ok := configs[name]; !ok {
			t.Errorf("missing config: %s", name)
		}
	}
}

// TestConfigSourceVariety tests that configs include various source types.
func TestConfigSourceVariety(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"SQLInjection", SQLInjection()},
		{"CommandInjection", CommandInjection()},
		{"PathTraversal", PathTraversal()},
		{"SSRF", SSRF()},
		{"XSS", XSS()},
		{"LogInjection", LogInjection()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each config should have at least one source
			if len(tt.config.Sources) == 0 {
				t.Error("config has no sources")
			}

			// Validate source structure
			for i, src := range tt.config.Sources {
				if src.Package == "" {
					t.Errorf("source[%d] has empty Package", i)
				}
				if src.Name == "" {
					t.Errorf("source[%d] has empty Name", i)
				}
			}
		})
	}
}

// TestConfigSinkVariety tests that configs include various sink types.
func TestConfigSinkVariety(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{"SQLInjection", SQLInjection()},
		{"CommandInjection", CommandInjection()},
		{"PathTraversal", PathTraversal()},
		{"SSRF", SSRF()},
		{"XSS", XSS()},
		{"LogInjection", LogInjection()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each config should have at least one sink
			if len(tt.config.Sinks) == 0 {
				t.Error("config has no sinks")
			}

			// Validate sink structure
			for i, sink := range tt.config.Sinks {
				if sink.Package == "" {
					t.Errorf("sink[%d] has empty Package", i)
				}
				if sink.Method == "" {
					t.Errorf("sink[%d] has empty Method", i)
				}
			}
		})
	}
}

// TestSQLInjectionSinks tests all SQL injection sinks.
func TestSQLInjectionSinks(t *testing.T) {
	config := SQLInjection()

	expectedSinks := []struct {
		receiver string
		method   string
	}{
		{"DB", "Query"},
		{"DB", "QueryContext"},
		{"DB", "QueryRow"},
		{"DB", "QueryRowContext"},
		{"DB", "Exec"},
		{"DB", "ExecContext"},
		{"Tx", "Query"},
		{"Tx", "QueryContext"},
		{"Tx", "Exec"},
		{"Tx", "ExecContext"},
	}

	for _, expected := range expectedSinks {
		found := false
		for _, sink := range config.Sinks {
			if sink.Receiver == expected.receiver && sink.Method == expected.method {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing sink: %s.%s", expected.receiver, expected.method)
		}
	}
}

// TestCommandInjectionSources tests command injection sources.
func TestCommandInjectionSources(t *testing.T) {
	config := CommandInjection()

	expectedSources := []struct {
		pkg  string
		name string
	}{
		{"net/http", "Request"},
		{"os", "Args"},
		{"bufio", "Reader"},
	}

	for _, expected := range expectedSources {
		found := false
		for _, src := range config.Sources {
			if src.Package == expected.pkg && src.Name == expected.name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing source: %s.%s", expected.pkg, expected.name)
		}
	}
}

// TestPathTraversalSinksCompleteness tests path traversal has comprehensive sinks.
func TestPathTraversalSinksCompleteness(t *testing.T) {
	config := PathTraversal()

	expectedMethods := []string{"Open", "OpenFile", "Create", "ReadFile", "WriteFile"}

	for _, method := range expectedMethods {
		found := false
		for _, sink := range config.Sinks {
			if sink.Method == method {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing method: %s", method)
		}
	}
}

// TestSSRFSinksCompleteness tests SSRF has comprehensive HTTP sinks.
func TestSSRFSinksCompleteness(t *testing.T) {
	config := SSRF()

	expectedMethods := []string{"Get", "Post", "Head", "Do"}

	found := make(map[string]bool)
	for _, sink := range config.Sinks {
		found[sink.Method] = true
	}

	for _, method := range expectedMethods {
		if !found[method] {
			t.Errorf("missing HTTP method: %s", method)
		}
	}
}

// TestXSSSinksVariety tests XSS has various output sinks.
func TestXSSSinksVariety(t *testing.T) {
	config := XSS()

	// Should have fmt and io sinks
	hasFmt := false
	hasIO := false

	for _, sink := range config.Sinks {
		if sink.Package == "fmt" {
			hasFmt = true
		}
		if sink.Package == "io" {
			hasIO = true
		}
	}

	if !hasFmt {
		t.Error("XSS config missing fmt package sinks")
	}

	if !hasIO {
		t.Error("XSS config missing io package sinks")
	}
}

// TestLogInjectionLoggerMethods tests log injection includes Logger methods.
func TestLogInjectionLoggerMethods(t *testing.T) {
	config := LogInjection()

	hasLoggerMethod := false
	for _, sink := range config.Sinks {
		if sink.Receiver == "Logger" {
			hasLoggerMethod = true
			break
		}
	}

	if !hasLoggerMethod {
		t.Error("LogInjection config missing Logger receiver methods")
	}
}
