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

// CodeInjection returns a configuration for detecting code injection
// vulnerabilities where user-controlled data is evaluated as code.
func CodeInjection() taint.Config {
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
			// yaegi Interpreter.Eval(src): Args[0] is the receiver, src is index 1.
			{Package: "github.com/traefik/yaegi/interp", Receiver: "Interpreter", Method: "Eval", Pointer: true, CheckArgs: []int{1}},
			// EvalWithContext(ctx, src): the source string is index 2.
			{Package: "github.com/traefik/yaegi/interp", Receiver: "Interpreter", Method: "EvalWithContext", Pointer: true, CheckArgs: []int{2}},

			// otto's Run has a value receiver: Otto.Run(src), src is index 1.
			{Package: "github.com/robertkrimen/otto", Receiver: "Otto", Method: "Run", Pointer: false, CheckArgs: []int{1}},

			// goja Runtime.RunString has a pointer receiver: src is index 1.
			{Package: "github.com/dop251/goja", Receiver: "Runtime", Method: "RunString", Pointer: true, CheckArgs: []int{1}},
		},
		Sanitizers: []taint.Sanitizer{
			// No general-purpose sanitizer exists for evaluating untrusted code.
			// The proper fix is to avoid evaluating user-controlled source.
		},
	}
}

// newCodeInjectionAnalyzer creates an analyzer for detecting code injection
// vulnerabilities via taint analysis (G713).
func newCodeInjectionAnalyzer(id string, description string) *analysis.Analyzer {
	config := CodeInjection()
	rule := CodeInjectionRule
	rule.ID = id
	rule.Description = description
	return taint.NewGosecAnalyzer(&rule, &config)
}
