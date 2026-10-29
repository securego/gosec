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

// LDAPInjection returns a configuration for detecting LDAP injection
// vulnerabilities where user-controlled data flows into an LDAP search filter.
func LDAPInjection() taint.Config {
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
			// ldap.NewSearchRequest(baseDN, scope, deref, sizeLimit, timeLimit,
			// typesOnly, filter, attributes, controls): filter is argument index 6.
			{Package: "github.com/go-ldap/ldap/v3", Method: "NewSearchRequest", CheckArgs: []int{6}},
		},
		Sanitizers: []taint.Sanitizer{
			// ldap.EscapeFilter escapes RFC 4515 filter metacharacters.
			{Package: "github.com/go-ldap/ldap/v3", Method: "EscapeFilter"},

			// Numeric conversions produce safe output.
			{Package: "strconv", Method: "Atoi"},
		},
	}
}

// newLDAPInjectionAnalyzer creates an analyzer for detecting LDAP injection
// vulnerabilities via taint analysis (G711).
func newLDAPInjectionAnalyzer(id string, description string) *analysis.Analyzer {
	config := LDAPInjection()
	rule := LDAPInjectionRule
	rule.ID = id
	rule.Description = description
	return taint.NewGosecAnalyzer(&rule, &config)
}
