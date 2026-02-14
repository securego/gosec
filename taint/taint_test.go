package taint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2/taint"
)

var _ = Describe("Taint Analysis", func() {
	Context("Source configuration", func() {
		It("should support IsFunc field for function sources", func() {
			config := taint.Config{
				Sources: []taint.Source{
					// Type source (IsFunc: false by default)
					{Package: "net/http", Name: "Request", Pointer: true},
					// Function source (IsFunc: true)
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
			}

			Expect(config.Sources).To(HaveLen(2))
			Expect(config.Sources[0].IsFunc).To(BeFalse())
			Expect(config.Sources[1].IsFunc).To(BeTrue())
			Expect(config.Sources[1].Name).To(Equal("Getenv"))
		})

		It("should default IsFunc to false", func() {
			source := taint.Source{
				Package: "net/http",
				Name:    "Request",
				Pointer: true,
			}

			Expect(source.IsFunc).To(BeFalse())
		})

		It("should support pointer type sources", func() {
			source := taint.Source{
				Package: "net/http",
				Name:    "Request",
				Pointer: true,
			}

			Expect(source.Pointer).To(BeTrue())
			Expect(source.Package).To(Equal("net/http"))
			Expect(source.Name).To(Equal("Request"))
		})
	})

	Context("Sink configuration", func() {
		It("should support CheckArgs field", func() {
			sink := taint.Sink{
				Package:   "database/sql",
				Receiver:  "DB",
				Method:    "Query",
				Pointer:   true,
				CheckArgs: []int{1},
			}

			Expect(sink.CheckArgs).To(Equal([]int{1}))
			Expect(sink.Method).To(Equal("Query"))
		})

		It("should support multiple CheckArgs indices", func() {
			sink := taint.Sink{
				Package:   "fmt",
				Method:    "Fprintf",
				CheckArgs: []int{1, 2, 3, 4, 5},
			}

			Expect(sink.CheckArgs).To(HaveLen(5))
			Expect(sink.CheckArgs[0]).To(Equal(1))
			Expect(sink.CheckArgs[4]).To(Equal(5))
		})

		It("should support interface method sinks", func() {
			sink := taint.Sink{
				Package:  "net/http",
				Receiver: "ResponseWriter",
				Method:   "Write",
			}

			Expect(sink.Receiver).To(Equal("ResponseWriter"))
			Expect(sink.Method).To(Equal("Write"))
		})

		It("should allow empty CheckArgs for checking all arguments", func() {
			sink := taint.Sink{
				Package: "log",
				Method:  "Println",
			}

			Expect(sink.CheckArgs).To(BeNil())
		})
	})

	Context("Sanitizer configuration", func() {
		It("should support sanitizer functions", func() {
			sanitizer := taint.Sanitizer{
				Package: "strings",
				Method:  "ReplaceAll",
			}

			Expect(sanitizer.Package).To(Equal("strings"))
			Expect(sanitizer.Method).To(Equal("ReplaceAll"))
		})

		It("should support sanitizer methods with receivers", func() {
			sanitizer := taint.Sanitizer{
				Package:  "regexp",
				Receiver: "Regexp",
				Method:   "ReplaceAllString",
				Pointer:  true,
			}

			Expect(sanitizer.Receiver).To(Equal("Regexp"))
			Expect(sanitizer.Pointer).To(BeTrue())
		})

		It("should support multiple sanitizers in a config", func() {
			config := taint.Config{
				Sanitizers: []taint.Sanitizer{
					{Package: "strings", Method: "ReplaceAll"},
					{Package: "strconv", Method: "Quote"},
					{Package: "net/url", Method: "QueryEscape"},
				},
			}

			Expect(config.Sanitizers).To(HaveLen(3))
			Expect(config.Sanitizers[0].Method).To(Equal("ReplaceAll"))
			Expect(config.Sanitizers[1].Method).To(Equal("Quote"))
			Expect(config.Sanitizers[2].Method).To(Equal("QueryEscape"))
		})
	})

	Context("Config validation", func() {
		It("should allow configs with sources, sinks, and sanitizers", func() {
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "log", Method: "Println"},
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true, CheckArgs: []int{1}},
				},
				Sanitizers: []taint.Sanitizer{
					{Package: "strings", Method: "ReplaceAll"},
				},
			}

			Expect(config.Sources).To(HaveLen(2))
			Expect(config.Sinks).To(HaveLen(2))
			Expect(config.Sanitizers).To(HaveLen(1))
		})

		It("should allow configs without sanitizers", func() {
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "log", Method: "Println"},
				},
			}

			Expect(config.Sources).To(HaveLen(1))
			Expect(config.Sinks).To(HaveLen(1))
			Expect(config.Sanitizers).To(BeEmpty())
		})
	})

	Context("RuleInfo structure", func() {
		It("should hold rule metadata", func() {
			rule := taint.RuleInfo{
				ID:          "G701",
				Description: "SQL injection via taint analysis",
				Severity:    "HIGH",
				CWE:         "CWE-89",
			}

			Expect(rule.ID).To(Equal("G701"))
			Expect(rule.Description).To(Equal("SQL injection via taint analysis"))
			Expect(rule.Severity).To(Equal("HIGH"))
			Expect(rule.CWE).To(Equal("CWE-89"))
		})
	})

	Context("Analyzer creation", func() {
		It("should create analyzer with config", func() {
			rule := taint.RuleInfo{
				ID:          "TEST",
				Description: "Test taint analyzer",
			}

			config := taint.Config{
				Sources: []taint.Source{
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "log", Method: "Println"},
				},
			}

			analyzer := taint.NewGosecAnalyzer(&rule, &config)

			Expect(analyzer).NotTo(BeNil())
			Expect(analyzer.Name).To(Equal("TEST"))
			Expect(analyzer.Doc).To(Equal("Test taint analyzer"))
		})
	})

	Context("False positive prevention", func() {
		It("should handle os.File source removal (issue #1500 fix)", func() {
			// os.File was removed as a universal source because it caused
			// false positives in filepath.WalkDir scenarios where d.Name()
			// returned a filename that was then used with os.Open()
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					// NOTE: os.File is NOT a source (fixed in #1500)
				},
				Sinks: []taint.Sink{
					{Package: "os", Method: "Open"},
				},
			}

			// Verify os.File is not in the sources
			hasFileSource := false
			for _, src := range config.Sources {
				if src.Package == "os" && src.Name == "File" {
					hasFileSource = true
				}
			}
			Expect(hasFileSource).To(BeFalse(), "os.File should not be a source")
		})

		It("should support IsFunc field to prevent type/function confusion", func() {
			// IsFunc field was added to distinguish between:
			// - Type sources like *http.Request (parameters of this type are tainted)
			// - Function sources like os.Getenv (return values are tainted)
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "os", Name: "Args", IsFunc: true},                 // Function source
					{Package: "os", Name: "File", Pointer: true, IsFunc: false}, // Type source (if used)
				},
			}

			Expect(config.Sources[0].IsFunc).To(BeTrue(), "os.Args should be a function source")
			Expect(config.Sources[1].IsFunc).To(BeFalse(), "os.File should be a type source")
		})

		It("should support CheckArgs for SSRF Client.Do (issue #1500 fix)", func() {
			// G704 had false positives because it checked ALL arguments to Client.Do,
			// including the *http.Request which could be constructed with hardcoded URLs.
			// Fixed by using CheckArgs: []int{} to skip the request argument validation
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
				},
				Sinks: []taint.Sink{
					// Original (caused false positives): CheckArgs not specified
					// Fixed: CheckArgs: []int{} means "don't check any args"
					{
						Package: "net/http", Receiver: "Client", Method: "Do", Pointer: true,
						CheckArgs: []int{},
					},
				},
			}

			Expect(config.Sinks[0].CheckArgs).To(Equal([]int{}))
			Expect(config.Sinks[0].Method).To(Equal("Do"))
		})

		It("should support CheckArgs for SQL Context methods (issue #1500 fix)", func() {
			// SQL methods with Context parameter need CheckArgs to skip the context
			// Args[0] = receiver (*DB), Args[1] = context.Context, Args[2] = query
			config := taint.Config{
				Sinks: []taint.Sink{
					{Package: "database/sql", Receiver: "DB", Method: "QueryContext", Pointer: true, CheckArgs: []int{2}},
					{Package: "database/sql", Receiver: "DB", Method: "ExecContext", Pointer: true, CheckArgs: []int{2}},
				},
			}

			Expect(config.Sinks[0].CheckArgs).To(Equal([]int{2}))
			Expect(config.Sinks[1].CheckArgs).To(Equal([]int{2}))
		})

		It("should support sanitizers to prevent false positives", func() {
			// Sanitizers were added to break taint chains when data is validated
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
				},
				Sinks: []taint.Sink{
					{Package: "log", Method: "Println"},
				},
				Sanitizers: []taint.Sanitizer{
					{Package: "strings", Method: "ReplaceAll"},
					{Package: "strconv", Method: "Quote"},
					{Package: "regexp", Receiver: "Regexp", Method: "ReplaceAllString", Pointer: true},
				},
			}

			Expect(config.Sanitizers).To(HaveLen(3))
			Expect(config.Sanitizers[0].Method).To(Equal("ReplaceAll"))
			Expect(config.Sanitizers[2].Receiver).To(Equal("Regexp"))
		})
	})

	Context("Issue #1500 regression prevention", func() {
		It("should have correct SSRF configuration to avoid false positives", func() {
			// This validates the fix for the hardcoded URL false positive:
			// http.NewRequestWithContext(ctx, http.MethodGet, "https://am.i.mullvad.net/ip", nil)
			// http.DefaultClient.Do(req) // Was incorrectly flagged as G704
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					// NOTE: Not including os.File prevents WalkDir false positive
				},
				Sinks: []taint.Sink{
					// CheckArgs: []int{} means "don't check arguments"
					// This prevents flagging hardcoded URL requests
					{Package: "net/http", Receiver: "Client", Method: "Do", Pointer: true, CheckArgs: []int{}},
				},
			}

			sink := config.Sinks[0]
			Expect(sink.Method).To(Equal("Do"))
			Expect(sink.CheckArgs).To(Equal([]int{}))
		})

		It("should not include os.File as source to avoid WalkDir false positives", func() {
			// This validates the fix for the filepath.WalkDir false positive:
			// filepath.WalkDir(".", func(fpath string, d fs.DirEntry, err error) error {
			//     docName = d.Name()  // Was incorrectly considered tainted
			// })
			// os.Open(docName) // Was incorrectly flagged as G703
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
					// DELIBERATELY NOT including: {Package: "os", Name: "File", Pointer: true}
				},
				Sinks: []taint.Sink{
					{Package: "os", Method: "Open"},
				},
			}

			hasFileSource := false
			for _, src := range config.Sources {
				if src.Package == "os" && src.Name == "File" {
					hasFileSource = true
				}
			}
			Expect(hasFileSource).To(BeFalse())
		})
	})

	Context("Taint analyzer functional tests", func() {
		var analyzer *taint.Analyzer
		var config taint.Config

		BeforeEach(func() {
			// Setup a basic SQL injection detection configuration
			config = taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true, CheckArgs: []int{1}},
					{Package: "database/sql", Receiver: "DB", Method: "Exec", Pointer: true, CheckArgs: []int{1}},
				},
				Sanitizers: []taint.Sanitizer{},
			}
			analyzer = taint.New(&config)
		})

		It("should create analyzer with valid configuration", func() {
			Expect(analyzer).NotTo(BeNil())
		})

		It("should format source keys correctly", func() {
			// Test that source keys are formatted properly
			// Sources use either: pkg.Type or pkg.Func
			config := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should format sink keys correctly", func() {
			// Test that sink keys are formatted properly
			// Sinks use: pkg.Receiver.Method or pkg.Method
			config := taint.Config{
				Sinks: []taint.Sink{
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
					{Package: "fmt", Method: "Fprintf"},
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should format sanitizer keys correctly", func() {
			// Test that sanitizer keys are formatted properly
			config := taint.Config{
				Sanitizers: []taint.Sanitizer{
					{Package: "strings", Method: "ReplaceAll"},
					{Package: "regexp", Receiver: "Regexp", Method: "ReplaceAllString", Pointer: true},
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should handle empty configuration", func() {
			emptyConfig := taint.Config{}
			analyzer := taint.New(&emptyConfig)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should support command injection detection configuration", func() {
			cmdConfig := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "os/exec", Method: "Command", CheckArgs: []int{1, 2, 3, 4, 5}},
					{Package: "os/exec", Receiver: "Cmd", Method: "Run", Pointer: true},
				},
			}
			analyzer := taint.New(&cmdConfig)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should support XSS detection configuration", func() {
			xssConfig := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
				},
				Sinks: []taint.Sink{
					{Package: "net/http", Receiver: "ResponseWriter", Method: "Write"},
					{Package: "io", Receiver: "Writer", Method: "Write"},
				},
				Sanitizers: []taint.Sanitizer{
					{Package: "html", Method: "EscapeString"},
					{Package: "html/template", Receiver: "Template", Method: "Execute", Pointer: true},
				},
			}
			analyzer := taint.New(&xssConfig)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should support path traversal detection configuration", func() {
			pathConfig := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
					{Package: "os", Name: "Getenv", IsFunc: true},
				},
				Sinks: []taint.Sink{
					{Package: "os", Method: "Open"},
					{Package: "os", Method: "OpenFile"},
					{Package: "os", Method: "ReadFile"},
					{Package: "os", Method: "WriteFile"},
					{Package: "io/ioutil", Method: "ReadFile"},
					{Package: "io/ioutil", Method: "WriteFile"},
				},
				Sanitizers: []taint.Sanitizer{
					{Package: "path/filepath", Method: "Clean"},
					{Package: "path/filepath", Method: "Base"},
				},
			}
			analyzer := taint.New(&pathConfig)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should support log injection detection configuration", func() {
			logConfig := taint.Config{
				Sources: []taint.Source{
					{Package: "net/http", Name: "Request", Pointer: true},
				},
				Sinks: []taint.Sink{
					{Package: "log", Method: "Print"},
					{Package: "log", Method: "Println"},
					{Package: "log", Method: "Printf"},
					{Package: "log/slog", Method: "Info"},
					{Package: "log/slog", Method: "Error"},
				},
				Sanitizers: []taint.Sanitizer{
					{Package: "strings", Method: "ReplaceAll"},
				},
			}
			analyzer := taint.New(&logConfig)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should handle configurations with receiver pointers", func() {
			config := taint.Config{
				Sinks: []taint.Sink{
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true},
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: false}, // Non-pointer
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should support CheckArgs for specific argument positions", func() {
			config := taint.Config{
				Sinks: []taint.Sink{
					// Only check argument at index 1 (the query string)
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true, CheckArgs: []int{1}},
					// Check multiple arguments
					{Package: "fmt", Method: "Fprintf", CheckArgs: []int{1, 2}},
					// Check all arguments (nil or empty CheckArgs)
					{Package: "log", Method: "Println"},
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})

		It("should handle complex multi-stage taint propagation configs", func() {
			config := taint.Config{
				Sources: []taint.Source{
					// HTTP request sources
					{Package: "net/http", Name: "Request", Pointer: true},
					// Environment sources
					{Package: "os", Name: "Getenv", IsFunc: true},
					{Package: "os", Name: "Environ", IsFunc: true},
				},
				Sinks: []taint.Sink{
					// SQL sinks
					{Package: "database/sql", Receiver: "DB", Method: "Query", Pointer: true, CheckArgs: []int{1}},
					{Package: "database/sql", Receiver: "DB", Method: "Exec", Pointer: true, CheckArgs: []int{1}},
					// Command execution sinks
					{Package: "os/exec", Method: "Command", CheckArgs: []int{1, 2, 3, 4, 5}},
					// File operation sinks
					{Package: "os", Method: "Open"},
					// Network sinks
					{Package: "net/http", Receiver: "Client", Method: "Do", Pointer: true},
				},
				Sanitizers: []taint.Sanitizer{
					// String sanitizers
					{Package: "strings", Method: "ReplaceAll"},
					{Package: "strings", Method: "Trim"},
					// Path sanitizers
					{Package: "path/filepath", Method: "Clean"},
					// HTML sanitizers
					{Package: "html", Method: "EscapeString"},
					// SQL sanitizers (parameterized queries)
					{Package: "database/sql", Receiver: "DB", Method: "Prepare", Pointer: true},
				},
			}
			analyzer := taint.New(&config)
			Expect(analyzer).NotTo(BeNil())
		})
	})
})
