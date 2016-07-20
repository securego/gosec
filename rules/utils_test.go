// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

package rules

import (
	"strings"
	"testing"

	gas "github.com/HewlettPackard/gas/core"
)

func gasTestRunner(source string, analyzer gas.Analyzer) []gas.Issue {
	analyzer.ProcessSource("dummy.go", source)
	return analyzer.Issues
}

func checkTestResults(t *testing.T, issues []gas.Issue, expected int, msg string) {
	found := len(issues)
	if found != expected {
		t.Errorf("Found %d issues, expected %d", found, expected)
	}

	for _, issue := range issues {
		if !strings.Contains(issue.What, msg) {
			t.Errorf("Unexpected issue identified: %s", issue.What)
		}
	}
}
