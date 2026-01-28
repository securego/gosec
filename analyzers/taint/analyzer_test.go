package taint

import (
	"go/token"
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
			analyzer := NewGosecAnalyzer(tt.rule, tt.config)

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

// TestDefaultAnalyzers tests the DefaultAnalyzers function.
func TestDefaultAnalyzers(t *testing.T) {
	analyzers := DefaultAnalyzers()

	if len(analyzers) != 6 {
		t.Errorf("expected 6 default analyzers, got %d", len(analyzers))
	}

	expectedIDs := map[string]bool{
		"G701": false,
		"G702": false,
		"G703": false,
		"G704": false,
		"G705": false,
		"G706": false,
	}

	for _, analyzer := range analyzers {
		if _, ok := expectedIDs[analyzer.Name]; !ok {
			t.Errorf("unexpected analyzer ID: %s", analyzer.Name)
		}
		expectedIDs[analyzer.Name] = true
	}

	// Check all expected IDs were found
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected analyzer %s not found", id)
		}
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
		if !contains(str, want) {
			t.Errorf("Finding.String() missing %q\nGot: %s", want, str)
		}
	}
}

// TestFindingStringWithoutPath tests Finding String with no path.
func TestFindingStringWithoutPath(t *testing.T) {
	finding := Finding{
		RuleID:      "G702",
		Description: "Command injection",
		Severity:    "CRITICAL",
		CWE:         "CWE-78",
		Filename:    "/path/to/file.go",
		Line:        10,
		Column:      5,
		Path:        []string{},
	}

	str := finding.String()

	if str == "" {
		t.Error("Finding.String() returned empty string")
	}

	// Should contain the rule info but not call path
	if !contains(str, "G702") {
		t.Error("Finding.String() missing rule ID")
	}

	if contains(str, "Call path:") {
		t.Error("Finding.String() should not include call path when empty")
	}
}

// TestAnalyzerResult tests AnalyzerResult structure.
func TestAnalyzerResult(t *testing.T) {
	result := AnalyzerResult{
		Findings: []Finding{
			{
				RuleID:      "G701",
				Description: "Test finding",
				Severity:    "HIGH",
				CWE:         "CWE-89",
				Filename:    "test.go",
				Line:        1,
				Column:      1,
			},
		},
	}

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}

	if result.Findings[0].RuleID != "G701" {
		t.Errorf("unexpected RuleID: %s", result.Findings[0].RuleID)
	}
}

// TestSeverityLevels tests that severity levels are appropriate.
func TestSeverityLevels(t *testing.T) {
	tests := []struct {
		rule           RuleInfo
		allowedLevels  []string
		expectedMinSev string
	}{
		{CommandInjectionRule, []string{"CRITICAL"}, "CRITICAL"},
		{SQLInjectionRule, []string{"HIGH", "CRITICAL"}, "HIGH"},
		{PathTraversalRule, []string{"HIGH", "CRITICAL"}, "HIGH"},
		{SSRFRule, []string{"HIGH", "CRITICAL"}, "HIGH"},
		{XSSRule, []string{"MEDIUM", "HIGH"}, "MEDIUM"},
		{LogInjectionRule, []string{"LOW", "MEDIUM"}, "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.rule.ID, func(t *testing.T) {
			found := false
			for _, level := range tt.allowedLevels {
				if tt.rule.Severity == level {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("severity %s not in allowed levels %v", tt.rule.Severity, tt.allowedLevels)
			}
		})
	}
}

// TestCWEMappings tests that CWE mappings are correct.
func TestCWEMappings(t *testing.T) {
	tests := []struct {
		rule        RuleInfo
		expectedCWE string
	}{
		{SQLInjectionRule, "CWE-89"},
		{CommandInjectionRule, "CWE-78"},
		{PathTraversalRule, "CWE-22"},
		{SSRFRule, "CWE-918"},
		{XSSRule, "CWE-79"},
		{LogInjectionRule, "CWE-117"},
	}

	for _, tt := range tests {
		t.Run(tt.rule.ID, func(t *testing.T) {
			if tt.rule.CWE != tt.expectedCWE {
				t.Errorf("CWE = %s, want %s", tt.rule.CWE, tt.expectedCWE)
			}
		})
	}
}

// TestFindingWithCode tests Finding with Code field.
func TestFindingWithCode(t *testing.T) {
	finding := Finding{
		RuleID:      "G701",
		Description: "Test",
		Severity:    "HIGH",
		CWE:         "CWE-89",
		Filename:    "test.go",
		Line:        1,
		Column:      1,
		Code:        "db.Query(query)",
	}

	if finding.Code != "db.Query(query)" {
		t.Errorf("unexpected Code: %s", finding.Code)
	}
}

// TestMakeAnalyzerRunner tests that the analyzer runner is created properly.
func TestMakeAnalyzerRunner(t *testing.T) {
	rule := SQLInjectionRule
	config := SQLInjection()

	runner := makeAnalyzerRunner(rule, config)

	if runner == nil {
		t.Fatal("makeAnalyzerRunner returned nil")
	}
}

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestResultWithPosition tests Result with valid position.
func TestResultWithPosition(t *testing.T) {
	fset := token.NewFileSet()
	file := fset.AddFile("test.go", -1, 100)
	pos := file.Pos(10)

	result := Result{
		Source:  Source{Package: "net/http", Name: "Request"},
		Sink:    Sink{Package: "database/sql", Method: "Query"},
		SinkPos: pos,
	}

	if result.SinkPos == token.NoPos {
		t.Error("expected valid position, got NoPos")
	}

	position := fset.Position(result.SinkPos)
	if position.Filename != "test.go" {
		t.Errorf("unexpected filename: %s", position.Filename)
	}
}

// TestAnalyzerResultEmpty tests empty analyzer result.
func TestAnalyzerResultEmpty(t *testing.T) {
	result := &AnalyzerResult{
		Findings: []Finding{},
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// TestFindingFields tests all Finding fields.
func TestFindingFields(t *testing.T) {
	finding := Finding{
		RuleID:      "G701",
		Description: "Test description",
		Severity:    "HIGH",
		CWE:         "CWE-89",
		Filename:    "test.go",
		Line:        10,
		Column:      5,
		Code:        "test code",
		Path:        []string{"main", "handler"},
	}

	if finding.RuleID != "G701" {
		t.Errorf("RuleID = %s, want G701", finding.RuleID)
	}

	if finding.Description != "Test description" {
		t.Errorf("Description = %s", finding.Description)
	}

	if finding.Severity != "HIGH" {
		t.Errorf("Severity = %s", finding.Severity)
	}

	if finding.CWE != "CWE-89" {
		t.Errorf("CWE = %s", finding.CWE)
	}

	if finding.Filename != "test.go" {
		t.Errorf("Filename = %s", finding.Filename)
	}

	if finding.Line != 10 {
		t.Errorf("Line = %d", finding.Line)
	}

	if finding.Column != 5 {
		t.Errorf("Column = %d", finding.Column)
	}

	if finding.Code != "test code" {
		t.Errorf("Code = %s", finding.Code)
	}

	if len(finding.Path) != 2 {
		t.Errorf("Path length = %d, want 2", len(finding.Path))
	}
}

// TestRuleInfoFields tests all RuleInfo fields.
func TestRuleInfoFields(t *testing.T) {
	rule := RuleInfo{
		ID:          "G999",
		Description: "Test rule",
		Severity:    "MEDIUM",
		CWE:         "CWE-999",
	}

	if rule.ID != "G999" {
		t.Errorf("ID = %s", rule.ID)
	}

	if rule.Description != "Test rule" {
		t.Errorf("Description = %s", rule.Description)
	}

	if rule.Severity != "MEDIUM" {
		t.Errorf("Severity = %s", rule.Severity)
	}

	if rule.CWE != "CWE-999" {
		t.Errorf("CWE = %s", rule.CWE)
	}
}
