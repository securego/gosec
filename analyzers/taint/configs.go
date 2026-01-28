package taint

// Predefined configurations for common security vulnerabilities.
// These can be used directly or as templates for custom configurations.

// SQLInjection returns a configuration for detecting SQL injection vulnerabilities.
func SQLInjection() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "URL", Pointer: true},
			{Package: "net/url", Name: "Values"},
		},
		Sinks: []Sink{
			{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryContext", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryRow", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "QueryRowContext", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "Exec", Pointer: true},
			{Package: "database/sql", Receiver: "DB", Method: "ExecContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "Query", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "QueryContext", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "Exec", Pointer: true},
			{Package: "database/sql", Receiver: "Tx", Method: "ExecContext", Pointer: true},
		},
	}
}

// CommandInjection returns a configuration for detecting command injection vulnerabilities.
func CommandInjection() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "bufio", Name: "Reader", Pointer: true},
		},
		Sinks: []Sink{
			{Package: "os/exec", Method: "Command"},
			{Package: "os/exec", Method: "CommandContext"},
			{Package: "syscall", Method: "Exec"},
			{Package: "syscall", Method: "ForkExec"},
		},
	}
}

// PathTraversal returns a configuration for detecting path traversal vulnerabilities.
func PathTraversal() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "URL", Pointer: true},
		},
		Sinks: []Sink{
			{Package: "os", Method: "Open"},
			{Package: "os", Method: "OpenFile"},
			{Package: "os", Method: "Create"},
			{Package: "os", Method: "ReadFile"},
			{Package: "os", Method: "WriteFile"},
			{Package: "io/ioutil", Method: "ReadFile"},
			{Package: "io/ioutil", Method: "WriteFile"},
		},
	}
}

// SSRF returns a configuration for detecting Server-Side Request Forgery vulnerabilities.
func SSRF() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "os", Name: "Args"},
			{Package: "os", Name: "Getenv"},
		},
		Sinks: []Sink{
			{Package: "net/http", Method: "Get"},
			{Package: "net/http", Method: "Post"},
			{Package: "net/http", Method: "Head"},
			{Package: "net/http", Method: "PostForm"},
			{Package: "net/http", Receiver: "Client", Method: "Do", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Get", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Post", Pointer: true},
			{Package: "net/http", Receiver: "Client", Method: "Head", Pointer: true},
		},
	}
}

// XSS returns a configuration for detecting Cross-Site Scripting vulnerabilities.
func XSS() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "Values"},
		},
		Sinks: []Sink{
			{Package: "net/http", Receiver: "ResponseWriter", Method: "Write"},
			{Package: "fmt", Method: "Fprintf"},
			{Package: "fmt", Method: "Fprint"},
			{Package: "fmt", Method: "Fprintln"},
			{Package: "io", Method: "WriteString"},
		},
	}
}

// LogInjection returns a configuration for detecting log injection vulnerabilities.
func LogInjection() Config {
	return Config{
		Sources: []Source{
			{Package: "net/http", Name: "Request", Pointer: true},
		},
		Sinks: []Sink{
			{Package: "log", Method: "Print"},
			{Package: "log", Method: "Printf"},
			{Package: "log", Method: "Println"},
			{Package: "log", Method: "Fatal"},
			{Package: "log", Method: "Fatalf"},
			{Package: "log", Method: "Fatalln"},
			{Package: "log", Receiver: "Logger", Method: "Print", Pointer: true},
			{Package: "log", Receiver: "Logger", Method: "Printf", Pointer: true},
			{Package: "log", Receiver: "Logger", Method: "Println", Pointer: true},
		},
	}
}

// AllConfigs returns all predefined taint configurations.
func AllConfigs() map[string]Config {
	return map[string]Config{
		"sql_injection":     SQLInjection(),
		"command_injection": CommandInjection(),
		"path_traversal":    PathTraversal(),
		"ssrf":              SSRF(),
		"xss":               XSS(),
		"log_injection":     LogInjection(),
	}
}
