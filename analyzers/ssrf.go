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

	"github.com/securego/gosec/v2/analyzers/taint"
)

// newSSRFAnalyzer creates an analyzer for detecting Server-Side Request Forgery vulnerabilities
// via taint analysis (G704)
func newSSRFAnalyzer(id string, description string) *analysis.Analyzer {
	config := taint.SSRF()
	rule := taint.RuleInfo{
		ID:          id,
		Description: description,
		Severity:    "HIGH",
		CWE:         "CWE-918",
	}
	return taint.NewGosecAnalyzer(&rule, &config)
}
