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

func (m *MockGenAIClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockGenAIClient) GenerativeModel(name string) GenAIGenerativeModel {
	args := m.Called(name)
	return args.Get(0).(GenAIGenerativeModel)
}

// MockGenAIGenerativeModel is a mock of the GenAIGenerativeModel interface
type MockGenAIGenerativeModel struct {
	mock.Mock
}

func (m *MockGenAIGenerativeModel) GenerateContent(ctx context.Context, prompt string) (string, error) {
	args := m.Called(ctx, prompt)
	return args.String(0), args.Error(1)
}

func TestGenerateSolutionByGemini_Success(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 1"},
	}

	mockClient := new(MockGenAIClient)
	mockModel := new(MockGenAIGenerativeModel)
	mockClient.On("GenerativeModel", GeminiModel).Return(mockModel).Once()
	mockModel.On("GenerateContent", mock.Anything, mock.Anything).Return("Autofix for issue 1", nil).Once()

	// Act
	err := generateSolutionByGemini(mockClient, issues)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, []*issue.Issue{{What: "Example issue 1", Autofix: "Autofix for issue 1"}}, issues)
	mock.AssertExpectationsForObjects(t, mockClient, mockModel)
}

func TestGenerateSolutionByGemini_NoCandidates(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 2"},
	}

	mockClient := new(MockGenAIClient)
	mockModel := new(MockGenAIGenerativeModel)
	mockClient.On("GenerativeModel", GeminiModel).Return(mockModel).Once()
	mockModel.On("GenerateContent", mock.Anything, mock.Anything).Return("", nil).Once()

	// Act
	err := generateSolutionByGemini(mockClient, issues)

	// Assert
	require.EqualError(t, err, "no autofix returned by gemini")
	mock.AssertExpectationsForObjects(t, mockClient, mockModel)
}

func TestGenerateSolutionByGemini_APIError(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 3"},
	}

	mockClient := new(MockGenAIClient)
	mockModel := new(MockGenAIGenerativeModel)
	mockClient.On("GenerativeModel", GeminiModel).Return(mockModel).Once()
	mockModel.On("GenerateContent", mock.Anything, mock.Anything).Return("", errors.New("API error")).Once()

	// Act
	err := generateSolutionByGemini(mockClient, issues)

	// Assert
	require.EqualError(t, err, "generating autofix with gemini: API error")
	mock.AssertExpectationsForObjects(t, mockClient, mockModel)
}

func TestGenerateSolution_UnsupportedProvider(t *testing.T) {
	// Arrange
	issues := []*issue.Issue{
		{What: "Example issue 4"},
	}

	// Act
	err := GenerateSolution("unsupported-provider", "test-api-key", "", issues)

	// Assert
	require.EqualError(t, err, "ai provider not supported")
}
