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
	"testing"
)

// TestTaintAnalyzerConstructors tests that all taint analyzer constructors work.
func TestTaintAnalyzerConstructors(t *testing.T) {
	tests := []struct {
		name        string
		constructor AnalyzerBuilder
		id          string
		description string
	}{
		{
			name:        "SQLInjection",
			constructor: newSQLInjectionAnalyzer,
			id:          "G701",
			description: "SQL injection via taint analysis",
		},
		{
			name:        "CommandInjection",
			constructor: newCommandInjectionAnalyzer,
			id:          "G702",
			description: "Command injection via taint analysis",
		},
		{
			name:        "PathTraversal",
			constructor: newPathTraversalAnalyzer,
			id:          "G703",
			description: "Path traversal via taint analysis",
		},
		{
			name:        "SSRF",
			constructor: newSSRFAnalyzer,
			id:          "G704",
			description: "SSRF via taint analysis",
		},
		{
			name:        "XSS",
			constructor: newXSSAnalyzer,
			id:          "G705",
			description: "XSS via taint analysis",
		},
		{
			name:        "LogInjection",
			constructor: newLogInjectionAnalyzer,
			id:          "G706",
			description: "Log injection via taint analysis",
		},
		{
			name:        "SMTPInjection",
			constructor: newSMTPInjectionAnalyzer,
			id:          "G707",
			description: "SMTP command/header injection via taint analysis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := tt.constructor(tt.id, tt.description)

			if analyzer == nil {
				t.Fatal("constructor returned nil")
			}

			if analyzer.Name != tt.id {
				t.Errorf("analyzer Name = %s, want %s", analyzer.Name, tt.id)
			}

			if analyzer.Run == nil {
				t.Error("analyzer Run function is nil")
			}

			if len(analyzer.Requires) == 0 {
				t.Error("analyzer has no requirements")
			}
		})
	}
}

// TestDefaultAnalyzersIncludeTaint tests that default analyzers include taint rules.
func TestDefaultAnalyzersIncludeTaint(t *testing.T) {
	expectedTaintIDs := []string{"G701", "G702", "G703", "G704", "G705", "G706", "G707"}

	found := make(map[string]bool)
	for _, def := range defaultAnalyzers {
		found[def.ID] = true
	}

	for _, id := range expectedTaintIDs {
		if !found[id] {
			t.Errorf("default analyzers missing taint rule: %s", id)
		}
	}
}

// TestGenerateIncludesTaintAnalyzers tests that Generate includes taint analyzers.
func TestGenerateIncludesTaintAnalyzers(t *testing.T) {
	analyzerList := Generate(false)

	expectedTaintIDs := []string{"G701", "G702", "G703", "G704", "G705", "G706", "G707"}

	for _, id := range expectedTaintIDs {
		if _, ok := analyzerList.Analyzers[id]; !ok {
			t.Errorf("generated analyzer list missing taint rule: %s", id)
		}
	}
}

// TestGenerateExcludeTaintAnalyzers tests that taint analyzers can be excluded.
func TestGenerateExcludeTaintAnalyzers(t *testing.T) {
	filter := NewAnalyzerFilter(true, "G701", "G702")
	analyzerList := Generate(false, filter)

	if _, ok := analyzerList.Analyzers["G701"]; ok {
		t.Error("G701 should be excluded but was found")
	}

	if _, ok := analyzerList.Analyzers["G702"]; ok {
		t.Error("G702 should be excluded but was found")
	}

	// Other taint analyzers should still be present
	if _, ok := analyzerList.Analyzers["G703"]; !ok {
		t.Error("G703 should be present but was not found")
	}
}

// TestNewAnalyzerFilter tests the filter creation with various scenarios.
func TestNewAnalyzerFilter(t *testing.T) {
	t.Run("Exclude specific analyzers", func(t *testing.T) {
		filter := NewAnalyzerFilter(true, "G701", "G702")

		if !filter("G701") {
			t.Error("G701 should be filtered (excluded)")
		}
		if !filter("G702") {
			t.Error("G702 should be filtered (excluded)")
		}
		if filter("G703") {
			t.Error("G703 should not be filtered")
		}
	})

	t.Run("Include only specific analyzers", func(t *testing.T) {
		filter := NewAnalyzerFilter(false, "G701", "G702")

		if filter("G701") {
			t.Error("G701 should be included")
		}
		if filter("G702") {
			t.Error("G702 should be included")
		}
		if !filter("G703") {
			t.Error("G703 should be filtered")
		}
	})

	t.Run("Empty filter list", func(t *testing.T) {
		filterExclude := NewAnalyzerFilter(true)
		filterInclude := NewAnalyzerFilter(false)

		if filterExclude("G701") {
			t.Error("With exclude=true and empty list, should not filter anything")
		}
		if !filterInclude("G701") {
			t.Error("With exclude=false and empty list, should filter everything")
		}
	})
}

// TestGenerateWithMultipleFilters tests using multiple filters together.
func TestGenerateWithMultipleFilters(t *testing.T) {
	filter1 := NewAnalyzerFilter(true, "G701")
	filter2 := NewAnalyzerFilter(true, "G702")

	analyzerList := Generate(false, filter1, filter2)

	if _, ok := analyzerList.Analyzers["G701"]; ok {
		t.Error("G701 should be excluded")
	}
	if _, ok := analyzerList.Analyzers["G702"]; ok {
		t.Error("G702 should be excluded")
	}
	if _, ok := analyzerList.Analyzers["G703"]; !ok {
		t.Error("G703 should be included")
	}
}

// TestGenerateWithTrackSuppressions tests the trackSuppressions flag.
func TestGenerateWithTrackSuppressions(t *testing.T) {
	filter := NewAnalyzerFilter(true, "G701", "G702")

	t.Run("Without tracking suppressions", func(t *testing.T) {
		analyzerList := Generate(false, filter)

		// Suppressed analyzers should not be in the map
		if _, ok := analyzerList.Analyzers["G701"]; ok {
			t.Error("G701 should not be in analyzer map when not tracking suppressions")
		}

		// But suppression status should still be tracked
		if !analyzerList.AnalyzerSuppressed["G701"] {
			t.Error("G701 should be marked as suppressed")
		}
	})

	t.Run("With tracking suppressions", func(t *testing.T) {
		analyzerList := Generate(true, filter)

		// Suppressed analyzers should be in the map when tracking
		if _, ok := analyzerList.Analyzers["G701"]; !ok {
			t.Error("G701 should be in analyzer map when tracking suppressions")
		}

		// And marked as suppressed
		if !analyzerList.AnalyzerSuppressed["G701"] {
			t.Error("G701 should be marked as suppressed")
		}
	})
}

// TestGenerateNoFilters tests generation with no filters.
func TestGenerateNoFilters(t *testing.T) {
	analyzerList := Generate(false)

	// All default analyzers should be present
	if len(analyzerList.Analyzers) != len(defaultAnalyzers) {
		t.Errorf("Expected %d analyzers, got %d", len(defaultAnalyzers), len(analyzerList.Analyzers))
	}

	// None should be suppressed
	for id, suppressed := range analyzerList.AnalyzerSuppressed {
		if suppressed {
			t.Errorf("Analyzer %s should not be suppressed with no filters", id)
		}
	}
}

// TestAnalyzerList_AnalyzersInfo tests the AnalyzersInfo method.
func TestAnalyzerList_AnalyzersInfo(t *testing.T) {
	analyzerList := Generate(false)

	builders, suppressedMap := analyzerList.AnalyzersInfo()

	if len(builders) != len(defaultAnalyzers) {
		t.Errorf("Expected %d builders, got %d", len(defaultAnalyzers), len(builders))
	}

	if len(suppressedMap) != len(defaultAnalyzers) {
		t.Errorf("Expected %d suppressed entries, got %d", len(defaultAnalyzers), len(suppressedMap))
	}

	// Verify all default analyzers are in builders
	for _, def := range defaultAnalyzers {
		if _, ok := builders[def.ID]; !ok {
			t.Errorf("Builder for %s not found", def.ID)
		}
	}
}

// TestDefaultTaintAnalyzers tests the DefaultTaintAnalyzers function.
func TestDefaultTaintAnalyzers(t *testing.T) {
	analyzers := DefaultTaintAnalyzers()

	expectedCount := 7 // SQL, Command, Path, SSRF, XSS, Log, SMTP
	if len(analyzers) != expectedCount {
		t.Errorf("Expected %d taint analyzers, got %d", expectedCount, len(analyzers))
	}

	expectedNames := map[string]bool{
		"G701": false,
		"G702": false,
		"G703": false,
		"G704": false,
		"G705": false,
		"G706": false,
		"G707": false,
	}

	for _, analyzer := range analyzers {
		if _, ok := expectedNames[analyzer.Name]; !ok {
			t.Errorf("Unexpected analyzer name: %s", analyzer.Name)
		}
		expectedNames[analyzer.Name] = true
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("Expected analyzer %s not found", name)
		}
	}
}

// TestBuildDefaultAnalyzers tests the BuildDefaultAnalyzers function.
func TestBuildDefaultAnalyzers(t *testing.T) {
	analyzers := BuildDefaultAnalyzers()

	if len(analyzers) == 0 {
		t.Error("BuildDefaultAnalyzers returned empty list")
	}

	// Should include G115, G602, G407
	expectedIDs := map[string]bool{
		"G115": false,
		"G602": false,
		"G407": false,
	}

	for _, analyzer := range analyzers {
		if _, ok := expectedIDs[analyzer.Name]; ok {
			expectedIDs[analyzer.Name] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("Expected default analyzer %s not found", id)
		}
	}
}

// TestTaintRuleConstants tests that taint rule constants are properly defined.
func TestTaintRuleConstants(t *testing.T) {
	// Test each rule directly
	t.Run("SQLInjection", func(t *testing.T) {
		if SQLInjectionRule.ID != "G701" {
			t.Errorf("ID = %s, want G701", SQLInjectionRule.ID)
		}
		if SQLInjectionRule.CWE != "CWE-89" {
			t.Errorf("CWE = %s, want CWE-89", SQLInjectionRule.CWE)
		}
		if SQLInjectionRule.Description == "" {
			t.Error("Description is empty")
		}
		if SQLInjectionRule.Severity == "" {
			t.Error("Severity is empty")
		}
	})

	t.Run("CommandInjection", func(t *testing.T) {
		if CommandInjectionRule.ID != "G702" {
			t.Errorf("ID = %s, want G702", CommandInjectionRule.ID)
		}
		if CommandInjectionRule.CWE != "CWE-78" {
			t.Errorf("CWE = %s, want CWE-78", CommandInjectionRule.CWE)
		}
	})

	t.Run("PathTraversal", func(t *testing.T) {
		if PathTraversalRule.ID != "G703" {
			t.Errorf("ID = %s, want G703", PathTraversalRule.ID)
		}
		if PathTraversalRule.CWE != "CWE-22" {
			t.Errorf("CWE = %s, want CWE-22", PathTraversalRule.CWE)
		}
	})

	t.Run("SSRF", func(t *testing.T) {
		if SSRFRule.ID != "G704" {
			t.Errorf("ID = %s, want G704", SSRFRule.ID)
		}
		if SSRFRule.CWE != "CWE-918" {
			t.Errorf("CWE = %s, want CWE-918", SSRFRule.CWE)
		}
	})

	t.Run("XSS", func(t *testing.T) {
		if XSSRule.ID != "G705" {
			t.Errorf("ID = %s, want G705", XSSRule.ID)
		}
		if XSSRule.CWE != "CWE-79" {
			t.Errorf("CWE = %s, want CWE-79", XSSRule.CWE)
		}
	})

	t.Run("LogInjection", func(t *testing.T) {
		if LogInjectionRule.ID != "G706" {
			t.Errorf("ID = %s, want G706", LogInjectionRule.ID)
		}
		if LogInjectionRule.CWE != "CWE-117" {
			t.Errorf("CWE = %s, want CWE-117", LogInjectionRule.CWE)
		}
	})

	t.Run("SMTPInjection", func(t *testing.T) {
		if SMTPInjectionRule.ID != "G707" {
			t.Errorf("ID = %s, want G707", SMTPInjectionRule.ID)
		}
		if SMTPInjectionRule.CWE != "CWE-93" {
			t.Errorf("CWE = %s, want CWE-93", SMTPInjectionRule.CWE)
		}
	})
}
