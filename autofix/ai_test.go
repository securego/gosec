package autofix

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/securego/gosec/v2/issue"
)

// MockGenAIClient is a mock of the GenAIClient interface
type MockGenAIClient struct {
	mock.Mock
}

func (m *MockGenAIClient) GenerateSolution(ctx context.Context, prompt string) (string, error) {
	args := m.Called(ctx, prompt)
	return args.String(0), args.Error(1)
}

func TestGenerateSolutionByGemini_Success(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 1"},
	}

	mockClient := new(MockGenAIClient)
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("Autofix for issue 1", nil).Once()

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, []*issue.Issue{{What: "Example issue 1", Autofix: "Autofix for issue 1"}}, issues)
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolutionByGemini_NoCandidates(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 2"},
	}

	mockClient := new(MockGenAIClient)
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("", nil).Once()

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.EqualError(t, err, "no autofix returned by gemini")
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolutionByGemini_APIError(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 3"},
	}

	mockClient := new(MockGenAIClient)
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("", errors.New("API error")).Once()

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.EqualError(t, err, "generating autofix with gemini: API error")
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolution_UnsupportedProvider(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 4"},
	}

	// Act
	// Note: With default OpenAI-compatible fallback, this will attempt to create an OpenAI client
	// The test will fail during client initialization due to missing/invalid API key or base URL
	err := GenerateSolution("custom-model", "", "", false, issues)

	// Assert
	// Expect an error during client initialization or API call
	require.Error(t, err)
}

func TestGenerateSolution_CachesSameIssue(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "SQL injection vulnerability"},
		{What: "SQL injection vulnerability"}, // Same issue
		{What: "XSS vulnerability"},
	}

	mockClient := new(MockGenAIClient)
	// Should only be called twice, not three times (cache hit on second SQL injection)
	mockClient.On("GenerateSolution", mock.Anything, mock.MatchedBy(func(prompt string) bool {
		return prompt == "Provide a brief explanation and a solution to fix this security issue\n  in Go programming language: \"SQL injection vulnerability\".\n  Answer in markdown format and keep the response limited to 200 words."
	})).Return("Fix SQL injection", nil).Once()
	mockClient.On("GenerateSolution", mock.Anything, mock.MatchedBy(func(prompt string) bool {
		return prompt == "Provide a brief explanation and a solution to fix this security issue\n  in Go programming language: \"XSS vulnerability\".\n  Answer in markdown format and keep the response limited to 200 words."
	})).Return("Fix XSS", nil).Once()

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "Fix SQL injection", issues[0].Autofix)
	assert.Equal(t, "Fix SQL injection", issues[1].Autofix) // Cached value
	assert.Equal(t, "Fix XSS", issues[2].Autofix)
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolution_MultipleIssues(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Issue 1"},
		{What: "Issue 2"},
		{What: "Issue 3"},
	}

	mockClient := new(MockGenAIClient)
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("Fix 1", nil).Once()
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("Fix 2", nil).Once()
	mockClient.On("GenerateSolution", mock.Anything, mock.Anything).Return("Fix 3", nil).Once()

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "Fix 1", issues[0].Autofix)
	assert.Equal(t, "Fix 2", issues[1].Autofix)
	assert.Equal(t, "Fix 3", issues[2].Autofix)
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolution_EmptyIssues(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{}
	mockClient := new(MockGenAIClient)

	// Act
	err := generateSolution(mockClient, issues)

	// Assert
	require.NoError(t, err)
	mock.AssertExpectationsForObjects(t, mockClient)
}

func TestGenerateSolution_ClaudeProvider(t *testing.T) {
	// Arrange - test with valid claude model but no API key
	issues := []*issue.Issue{{What: "Test issue"}}

	// Act
	err := GenerateSolution("claude-sonnet-4-0", "", "", false, issues)

	// Assert
	// Without a real API key, we expect an error from the API
	require.Error(t, err)
}

func TestGenerateSolution_GeminiProvider(t *testing.T) {
	// Arrange - test with valid gemini model but no API key
	issues := []*issue.Issue{{What: "Test issue"}}

	// Act
	err := GenerateSolution("gemini-2.0-flash", "", "", false, issues)

	// Assert
	// Without a real API key, we expect an error from the API
	require.Error(t, err)
}

func TestGenerateSolution_OpenAIProvider(t *testing.T) {
	// Arrange - test with valid openai model but no API key
	issues := []*issue.Issue{{What: "Test issue"}}

	// Act
	err := GenerateSolution("gpt-4o", "", "", false, issues)

	// Assert
	// Without a real API key, we expect an error from the API
	require.Error(t, err)
}
