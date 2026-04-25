package autofix

import (
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAnthropicModel_AllModels(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected anthropic.Model
	}{
		{
			name:     "claude-opus-4-7",
			input:    "claude-opus-4-7",
			expected: anthropic.ModelClaudeOpus4_7,
		},
		{
			name:     "claude-sonnet-4-6",
			input:    "claude-sonnet-4-6",
			expected: anthropic.ModelClaudeSonnet4_6,
		},
		{
			name:     "claude-sonnet",
			input:    "claude-sonnet",
			expected: anthropic.ModelClaudeSonnet4_6,
		},
		{
			name:     "claude-opus-4-6",
			input:    "claude-opus-4-6",
			expected: anthropic.ModelClaudeOpus4_6,
		},
		{
			name:     "claude-opus",
			input:    "claude-opus",
			expected: anthropic.ModelClaudeOpus4_6,
		},
		{
			name:     "claude-sonnet-4-5",
			input:    "claude-sonnet-4-5",
			expected: anthropic.ModelClaudeSonnet4_5_20250929,
		},
		{
			name:     "claude-sonnet-4-5-20250929",
			input:    "claude-sonnet-4-5-20250929",
			expected: anthropic.ModelClaudeSonnet4_5_20250929,
		},
		{
			name:     "claude-opus-4-5",
			input:    "claude-opus-4-5",
			expected: anthropic.ModelClaudeOpus4_5_20251101,
		},
		{
			name:     "claude-opus-4-5-20251101",
			input:    "claude-opus-4-5-20251101",
			expected: anthropic.ModelClaudeOpus4_5_20251101,
		},
		{
			name:     "claude-haiku-4-5",
			input:    "claude-haiku-4-5",
			expected: anthropic.ModelClaudeHaiku4_5_20251001,
		},
		{
			name:     "claude-haiku-4-5-20251001",
			input:    "claude-haiku-4-5-20251001",
			expected: anthropic.ModelClaudeHaiku4_5_20251001,
		},
		{
			name:     "default to claude-sonnet-4-6",
			input:    "unknown-model",
			expected: anthropic.ModelClaudeSonnet4_6,
		},
		{
			name:     "empty string defaults to claude-sonnet-4-6",
			input:    "",
			expected: anthropic.ModelClaudeSonnet4_6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAnthropicModel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewClaudeClient_WithModel(t *testing.T) {
	tests := []struct {
		name   string
		model  string
		apiKey string
	}{
		{
			name:   "claude-sonnet-4-6 with API key",
			model:  "claude-sonnet-4-6",
			apiKey: "test-api-key",
		},
		{
			name:   "claude-opus-4-6 with API key",
			model:  "claude-opus-4-6",
			apiKey: "test-api-key",
		},
		{
			name:   "claude-haiku-4-5 with API key",
			model:  "claude-haiku-4-5",
			apiKey: "test-api-key",
		},
		{
			name:   "empty API key",
			model:  "claude-sonnet-4-6",
			apiKey: "",
		},
		{
			name:   "unknown model defaults to sonnet",
			model:  "claude-unknown",
			apiKey: "test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClaudeClient(tt.model, tt.apiKey)
			require.NoError(t, err)
			assert.NotNil(t, client)

			// Verify wrapper type
			wrapper, ok := client.(*claudeWrapper)
			require.True(t, ok, "client should be claudeWrapper type")
			assert.NotNil(t, wrapper.client)
		})
	}
}

func TestNewClaudeClient_ModelMapping(t *testing.T) {
	tests := []struct {
		modelInput    string
		expectedModel anthropic.Model
	}{
		{"claude-opus-4-7", anthropic.ModelClaudeOpus4_7},
		{"claude-sonnet-4-6", anthropic.ModelClaudeSonnet4_6},
		{"claude-sonnet", anthropic.ModelClaudeSonnet4_6},
		{"claude-opus-4-6", anthropic.ModelClaudeOpus4_6},
		{"claude-opus", anthropic.ModelClaudeOpus4_6},
		{"claude-sonnet-4-5", anthropic.ModelClaudeSonnet4_5_20250929},
		{"claude-sonnet-4-5-20250929", anthropic.ModelClaudeSonnet4_5_20250929},
		{"claude-opus-4-5", anthropic.ModelClaudeOpus4_5_20251101},
		{"claude-opus-4-5-20251101", anthropic.ModelClaudeOpus4_5_20251101},
		{"claude-haiku-4-5", anthropic.ModelClaudeHaiku4_5_20251001},
		{"claude-haiku-4-5-20251001", anthropic.ModelClaudeHaiku4_5_20251001},
		{"unknown-model", anthropic.ModelClaudeSonnet4_6}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.modelInput, func(t *testing.T) {
			client, err := NewClaudeClient(tt.modelInput, "test-key")
			require.NoError(t, err)

			wrapper := client.(*claudeWrapper)
			assert.Equal(t, tt.expectedModel, wrapper.model)
		})
	}
}

func TestClaudeWrapper_ClientProperties(t *testing.T) {
	client, err := NewClaudeClient("claude-sonnet-4-6", "test-api-key")
	require.NoError(t, err)
	require.NotNil(t, client)

	wrapper, ok := client.(*claudeWrapper)
	require.True(t, ok)

	// Verify client was initialized
	assert.NotNil(t, wrapper.client)
	assert.Equal(t, anthropic.ModelClaudeSonnet4_6, wrapper.model)
}

func TestClaudeModel_Constants(t *testing.T) {
	// Verify model constants are properly defined
	assert.Equal(t, anthropic.ModelClaudeOpus4_7, ModelClaudeOpus4_7)
	assert.Equal(t, anthropic.ModelClaudeOpus4_6, ModelClaudeOpus4_6)
	assert.Equal(t, anthropic.ModelClaudeSonnet4_6, ModelClaudeSonnet4_6)
	assert.Equal(t, anthropic.ModelClaudeOpus4_5_20251101, ModelClaudeOpus4_5)
	assert.Equal(t, anthropic.ModelClaudeSonnet4_5_20250929, ModelClaudeSonnet4_5)
	assert.Equal(t, anthropic.ModelClaudeHaiku4_5_20251001, ModelClaudeHaiku4_5)
}

func TestClaudeWrapper_ImplementsInterface(t *testing.T) {
	var _ GenAIClient = (*claudeWrapper)(nil)
}

func TestNewClaudeClient_WithEmptyAPIKey(t *testing.T) {
	// Test that client creation succeeds even with empty API key
	// (authentication will fail at API call time)
	client, err := NewClaudeClient("claude-sonnet-4-6", "")
	require.NoError(t, err)
	assert.NotNil(t, client)

	wrapper := client.(*claudeWrapper)
	assert.NotNil(t, wrapper.client)
}

func TestNewClaudeClient_AllSupportedModels(t *testing.T) {
	models := []string{
		"claude-sonnet",
		"claude-opus",
		"claude-opus-4-7",
		"claude-sonnet-4-6",
		"claude-opus-4-6",
		"claude-sonnet-4-5",
		"claude-sonnet-4-5-20250929",
		"claude-opus-4-5",
		"claude-opus-4-5-20251101",
		"claude-haiku-4-5",
		"claude-haiku-4-5-20251001",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			client, err := NewClaudeClient(model, "test-key")
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}
