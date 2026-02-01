package taint

import (
	"strings"
	"testing"
)

// TestRuleInfo tests the RuleInfo structure.
func TestRuleInfo(t *testing.T) {
	tests := []struct {
		name string
		rule RuleInfo
	}{
		{
			name: "SQLInjectionRule",
			rule: SQLInjectionRule,
		},
		{
			name: "CommandInjectionRule",
			rule: CommandInjectionRule,
		},
		{
			name: "PathTraversalRule",
			rule: PathTraversalRule,
		},
		{
			name: "SSRFRule",
			rule: SSRFRule,
		},
		{
			name: "XSSRule",
			rule: XSSRule,
		},
		{
			name: "LogInjectionRule",
			rule: LogInjectionRule,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.rule.ID == "" {
				t.Error("rule ID is empty")
			}

			if tt.rule.Description == "" {
				t.Error("rule Description is empty")
			}

			if tt.rule.Severity == "" {
				t.Error("rule Severity is empty")
			}

			if tt.rule.CWE == "" {
				t.Error("rule CWE is empty")
			}

			// Validate ID format (should be G7XX)
			if len(tt.rule.ID) < 4 || tt.rule.ID[0] != 'G' || tt.rule.ID[1] != '7' {
				t.Errorf("rule ID has unexpected format: %s", tt.rule.ID)
			}

			// Validate CWE format
			if len(tt.rule.CWE) < 6 || tt.rule.CWE[0:4] != "CWE-" {
				t.Errorf("CWE has unexpected format: %s", tt.rule.CWE)
			}
		})
	}
}

// TestNewGosecAnalyzer tests the analyzer constructor.
func TestNewGosecAnalyzer(t *testing.T) {
	tests := []struct {
		name   string
		rule   RuleInfo
		config Config
	}{
		{
			name:   "SQLInjection",
			rule:   SQLInjectionRule,
			config: SQLInjection(),
		},
		{
			name:   "CommandInjection",
			rule:   CommandInjectionRule,
			config: CommandInjection(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewGosecAnalyzer(&tt.rule, &tt.config)

			if analyzer == nil {
				t.Fatal("NewGosecAnalyzer returned nil")
			}

			if analyzer.Name != tt.rule.ID {
				t.Errorf("analyzer Name = %s, want %s", analyzer.Name, tt.rule.ID)
			}

			if analyzer.Doc != tt.rule.Description {
				t.Errorf("analyzer Doc = %s, want %s", analyzer.Doc, tt.rule.Description)
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

// TestFindingString tests the Finding String method.
func TestFindingString(t *testing.T) {
	finding := Finding{
		RuleID:      "G701",
		Description: "SQL injection",
		Severity:    "HIGH",
		CWE:         "CWE-89",
		Filename:    "/path/to/file.go",
		Line:        42,
		Column:      10,
		Path:        []string{"main", "handler", "buildQuery"},
	}

	str := finding.String()

	if str == "" {
		t.Error("Finding.String() returned empty string")
	}

	// Check that the string contains key information
	tests := []string{
		"G701",
		"SQL injection",
		"HIGH",
		"CWE-89",
		"/path/to/file.go",
		"42",
		"10",
		"main -> handler -> buildQuery",
	}

	for _, want := range tests {
		if !strings.Contains(str, want) {
			t.Errorf("Finding.String() missing %q\nGot: %s", want, str)
		}
	}
}

// TestMakeAnalyzerRunner tests that the analyzer runner is created properly.
func TestMakeAnalyzerRunner(t *testing.T) {
	rule := SQLInjectionRule
	config := SQLInjection()

	runner := makeAnalyzerRunner(&rule, &config)

	if runner == nil {
		t.Fatal("makeAnalyzerRunner returned nil")
	}
}
