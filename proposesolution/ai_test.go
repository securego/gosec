package proposesolution_test

import (
	"testing"

	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/proposesolution"
)

func TestGenerateSolution(t *testing.T) {
	aiApiProvider := proposesolution.GeminiProvider
	aiApiKey := "test-api-key" // Replace with a valid API key for actual testing

	issues := []*issue.Issue{
		{
			What: "Blocklisted import crypto/md5: weak cryptographic primitive",
		},
	}

	err := proposesolution.GenerateSolution(aiApiProvider, aiApiKey, issues)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	for _, issue := range issues {
		if issue.ProposedSolution == "" {
			t.Errorf("Expected a proposed solution, got an empty string")
		}
	}
}
