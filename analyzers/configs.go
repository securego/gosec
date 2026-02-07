package analyzers

import (
	"github.com/securego/gosec/v2/taint"
)

// Predefined configurations for common security vulnerabilities.
// These can be used directly or as templates for custom configurations.

// SQLInjection returns a configuration for detecting SQL injection vulnerabilities.
func SQLInjection() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "URL", Pointer: true},
			{Package: "net/url", Name: "Values"},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryContext", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryRow", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryRowContext", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "Exec", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "ExecContext", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "Prepare", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "PrepareContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "Query", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "QueryContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "QueryRow", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "QueryRowContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "Exec", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "ExecContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "Prepare", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "PrepareContext", Pointer: true},
		},
	}
}

// CommandInjection returns a configuration for detecting command injection vulnerabilities.
func CommandInjection() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "os/exec", Method: "Command"},
			{Package: "os/exec", Method: "CommandContext"},
			{Package: "os/exec", Receiver: "Cmd", Method: "Start", Pointer: true},
			{Package: "os/exec", Receiver: "Cmd", Method: "Run", Pointer: true},
			{Package: "os/exec", Receiver: "Cmd", Method: "Output", Pointer: true},
			{Package: "os/exec", Receiver: "Cmd", Method: "CombinedOutput", Pointer: true},
			{Package: "os", Method: "StartProcess"},
			{Package: "syscall", Method: "Exec"},
			{Package: "syscall", Method: "ForkExec"},
			{Package: "syscall", Method: "StartProcess"},
		},
	}
}

// PathTraversal returns a configuration for detecting path traversal vulnerabilities.
func PathTraversal() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "URL", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "os", Method: "Open"},
			{Package: "os", Method: "OpenFile"},
			{Package: "os", Method: "Create"},
			{Package: "os", Method: "ReadFile"},
			{Package: "os", Method: "WriteFile"},
			{Package: "os", Method: "Remove"},
			{Package: "os", Method: "RemoveAll"},
			{Package: "os", Method: "Rename"},
			{Package: "os", Method: "Mkdir"},
			{Package: "os", Method: "MkdirAll"},
			{Package: "os", Method: "Stat"},
			{Package: "os", Method: "Lstat"},
			{Package: "os", Method: "Chmod"},
			{Package: "os", Method: "Chown"},
			{Package: "io/ioutil", Method: "ReadFile"},
			{Package: "io/ioutil", Method: "WriteFile"},
			{Package: "io/ioutil", Method: "ReadDir"},
			{Package: "path/filepath", Method: "Walk"},
			{Package: "path/filepath", Method: "WalkDir"},
		},
	}
}

// SSRF returns a configuration for detecting Server-Side Request Forgery vulnerabilities.
func SSRF() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "net/http", Method: "Get"},
			{Package: "net/http", Method: "Post"},
			{Package: "net/http", Method: "Head"},
			{Package: "net/http", Method: "PostForm"},
			{Package: "net/http", Method: "NewRequest"},
			{Package: "net/http", Receiver: "Client", Method: "Do", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Get", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Post", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Head", Pointer: true},
			{Package: "net", Method: "Dial"},
			{Package: "net", Method: "DialTimeout"},
			{Package: "net", Method: "LookupHost"},
			{Package: "net/http/httputil", Method: "NewSingleHostReverseProxy"},
			{Package: "net/http/httputil", Receiver: "ReverseProxy", Method: "ServeHTTP", Pointer: true},
		},
	}
}

// XSS returns a configuration for detecting Cross-Site Scripting vulnerabilities.
func XSS() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "Values"},
			{Package: "os", Name: "Args"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "net/http", Receiver: "ResponseWriter", Method: "Write"},
			{Package: "fmt", Method: "Fprintf"},
			{Package: "fmt", Method: "Fprint"},
			{Package: "fmt", Method: "Fprintln"},
			{Package: "io", Method: "WriteString"},
			{Package: "html/template", Method: "HTML"},
			{Package: "html/template", Method: "HTMLAttr"},
			{Package: "html/template", Method: "JS"},
			{Package: "html/template", Method: "CSS"},
		},
	}
}

// LogInjection returns a configuration for detecting log injection vulnerabilities.
func LogInjection() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
			{Package: "os", Name: "File", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "log", Method: "Print"},
			{Package: "log", Method: "Printf"},
			{Package: "log", Method: "Println"},
			{Package: "log", Method: "Fatal"},
			{Package: "log", Method: "Fatalf"},
			{Package: "log", Method: "Fatalln"},
			{Package: "log", Method: "Panic"},
			{Package: "log", Method: "Panicf"},
			{Package: "log", Method: "Panicln"},
			{Package: "log", Receiver: "Logger", Method: "Print", Pointer: true},
			{Package: "log", Receiver: "Logger", Method: "Printf", Pointer: true},
			{Package: "log", Receiver: "Logger", Method: "Println", Pointer: true},
			{Package: "log/slog", Method: "Info"},
			{Package: "log/slog", Method: "Error"},
			{Package: "log/slog", Method: "Warn"},
			{Package: "log/slog", Method: "Debug"},
			{Package: "log/slog", Receiver: "Logger", Method: "Info", Pointer: true},
			{Package: "log/slog", Receiver: "Logger", Method: "Error", Pointer: true},
			{Package: "log/slog", Receiver: "Logger", Method: "Warn", Pointer: true},
			{Package: "log/slog", Receiver: "Logger", Method: "Debug", Pointer: true},
		},
	}
}

// AllConfigs returns all predefined taint configurations.
func AllConfigs() map[string]taint.Config {
	return map[string]taint.Config{
		"sql_injection":     SQLInjection(),
		"command_injection": CommandInjection(),
		"path_traversal":    PathTraversal(),
		"ssrf":              SSRF(),
		"xss":               XSS(),
		"log_injection":     LogInjection(),
	}
}
