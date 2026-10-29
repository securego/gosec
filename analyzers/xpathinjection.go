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

// XPathInjection returns a configuration for detecting XPath injection
// vulnerabilities where user-controlled data flows into an XPath expression.
func XPathInjection() taint.Config {
	return taint.Config{
		Sources: []taint.Source{
			// Type sources: tainted when received as parameters
			{Package: "net/http", Name: "Request", Pointer: true},
			{Package: "net/url", Name: "URL", Pointer: true},
			{Package: "net/url", Name: "Values"},
			{Package: "bufio", Name: "Reader", Pointer: true},
			{Package: "bufio", Name: "Scanner", Pointer: true},

			// Function sources
			{Package: "os", Name: "Args", IsFunc: true},
			{Package: "os", Name: "Getenv", IsFunc: true},
		},
		Sinks: []taint.Sink{
			// xmlquery.Find(top, expr): the XPath expression is argument index 1.
			{Package: "github.com/antchfx/xmlquery", Method: "Find", CheckArgs: []int{1}},
			{Package: "github.com/antchfx/xmlquery", Method: "FindOne", CheckArgs: []int{1}},
			{Package: "github.com/antchfx/xmlquery", Method: "FindEach", CheckArgs: []int{1}},
			{Package: "github.com/antchfx/xmlquery", Method: "FindEachWithBreak", CheckArgs: []int{1}},

			// antchfx/xpath.Compile / MustCompile take the expression as argument 0.
			{Package: "github.com/antchfx/xpath", Method: "Compile", CheckArgs: []int{0}},
			{Package: "github.com/antchfx/xpath", Method: "MustCompile", CheckArgs: []int{0}},
		},
		Sanitizers: []taint.Sanitizer{
			// No widely accepted XPath escaping API exists for Go.
			// Prefer fixed expressions with variable binding instead.
		},
	}
}

// newXPathInjectionAnalyzer creates an analyzer for detecting XPath injection
// vulnerabilities via taint analysis (G712).
func newXPathInjectionAnalyzer(id string, description string) *analysis.Analyzer {
	config := XPathInjection()
	rule := XPathInjectionRule
	rule.ID = id
	rule.Description = description
	return taint.NewGosecAnalyzer(&rule, &config)
}
