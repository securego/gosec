package autofix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAtlasModel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "atlas defaults to deepseek v3",
			input:    "atlas",
			expected: ModelAtlasDefault,
		},
		{
			name:     "atlas deepseek alias",
			input:    "atlas-deepseek-v4-flash",
			expected: ModelAtlasDeepSeekV4Flash,
		},
		{
			name:     "atlas qwen alias",
			input:    "atlas-qwen3-coder-next",
			expected: ModelAtlasQwenCoderNext,
		},
		{
			name:     "atlas kimi alias",
			input:    "atlas-kimi-k2.6",
			expected: ModelAtlasKimiK26,
		},
		{
			name:     "atlas slash syntax",
			input:    "atlas/deepseek-v3",
			expected: "deepseek-v3",
		},
		{
			name:     "atlas colon syntax",
			input:    "atlas:qwen-plus",
			expected: "qwen-plus",
		},
		{
			name:     "unknown non atlas model passes through",
			input:    "custom-model",
			expected: "custom-model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseAtlasModel(tt.input))
		})
	}
}

func TestNewAtlasClient_Defaults(t *testing.T) {
	client, err := NewAtlasClient(AtlasConfig{
		Model:  "atlas",
		APIKey: "test-key",
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	wrapper, ok := client.(*openaiWrapper)
	require.True(t, ok)
	assert.Equal(t, ModelAtlasDefault, string(wrapper.model))
	assert.Equal(t, 1024, wrapper.maxTokens)
	assert.InEpsilon(t, 0.7, wrapper.temperature, 0.001)
}

func TestNewAtlasClient_CustomModelSyntax(t *testing.T) {
	client, err := NewAtlasClient(AtlasConfig{
		Model:   "atlas/moonshot-v1-8k",
		APIKey:  "test-key",
		BaseURL: DefaultAtlasBaseURL,
	})
	require.NoError(t, err)

	wrapper := client.(*openaiWrapper)
	assert.Equal(t, "moonshot-v1-8k", string(wrapper.model))
}
