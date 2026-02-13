// (c) Copyright gosec's authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
	"golang.org/x/tools/go/analysis"

	"github.com/securego/gosec/v2/taint"
)

// XSS returns a configuration for detecting Cross-Site Scripting vulnerabilities.
func XSS() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			// Type sources: tainted when received as parameters
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "Values"},

			// Function sources
			{Package: "os", Name: "Args", IsFunc: true},

			// I/O sources
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},
		},
		Sinks: []taint.Sink{
			{Package: "net/http", Receiver: "ResponseWriter", Method: "Write"},
			// For fmt print functions, Args[0] is writer - skip it, check format and data args
			{Package: "fmt", Method: "Fprintf", CheckArgs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			{Package: "fmt", Method: "Fprint", CheckArgs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			{Package: "fmt", Method: "Fprintln", CheckArgs: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			{Package: "io", Method: "WriteString", CheckArgs: []int{1}},
			// Template functions that unsafely inject untrusted content
			{Package: "html/template", Method: "HTML"},
			{Package: "html/template", Method: "HTMLAttr"},
			{Package: "html/template", Method: "JS"},
			{Package: "html/template", Method: "CSS"},
		},
		Sanitizers: []taint.Sanitizer{
			// html.EscapeString escapes HTML special characters
			{Package: "html", Method: "EscapeString"},
			// html/template auto-escaping functions
			{Package: "html/template", Method: "HTMLEscapeString"},
			{Package: "html/template", Method: "JSEscapeString"},
			{Package: "html/template", Method: "URLQueryEscaper"},
			// url.QueryEscape for URL parameter escaping
			{Package: "net/url", Method: "QueryEscape"},
			{Package: "net/url", Method: "PathEscape"},
		},
	}
}

// newXSSAnalyzer creates an analyzer for detecting XSS vulnerabilities
// via taint analysis (G705)
func newXSSAnalyzer(id string, description string) *analysis.Analyzer {
	config := XSS()
	rule := XSSRule
	rule.ID = id
	rule.Description = description
	return taint.NewGosecAnalyzer(&rule, &config)
}
