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

package goanalysis_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/securego/gosec/v2/goanalysis"
)

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, goanalysis.Analyzer, "a")

	// Verify we found some issues
	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	foundIssues := 0
	for _, result := range results {
		foundIssues += len(result.Diagnostics)
		for _, diag := range result.Diagnostics {
			t.Logf("Found: %s: %s", diag.Category, diag.Message)
		}
	}

	if foundIssues == 0 {
		t.Fatal("Expected to find security issues but found none")
	}

	// We expect to find G501, G204, and G401 issues
	expectedIssues := 3
	if foundIssues != expectedIssues {
		t.Errorf("Expected %d issues, found %d", expectedIssues, foundIssues)
	}
}
