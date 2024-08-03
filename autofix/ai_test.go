package autofix

import (
	"testing"

	"github.com/securego/gosec/v2/issue"
)

func TestGenerateSolution(t *testing.T) {
	aiApiProvider := GeminiProvider
	aiApiKey := "test-api-key" // Replace with a valid API key for actual testing

	issues := []*issue.Issue{
		{
			What: "Blocklisted import crypto/md5: weak cryptographic primitive",
		},
	}

	err := GenerateSolution(aiApiProvider, aiApiKey, issues)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	for _, issue := range issues {
		if issue.AutoFix == "" {
			t.Errorf("Expected a proposed solution, got an empty string")
		}
	}
}
