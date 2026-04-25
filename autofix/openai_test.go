package autofix

import (
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpenAIModel_AllModels(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected openai.ChatModel
	}{
		{
			name:     "gpt-5.4",
			input:    "gpt-5.4",
			expected: openai.ChatModelGPT5_4,
		},
		{
			name:     "gpt-5.4-mini",
			input:    "gpt-5.4-mini",
			expected: openai.ChatModelGPT5_4Mini,
		},
		{
			name:     "gpt-5.4-nano",
			input:    "gpt-5.4-nano",
			expected: openai.ChatModelGPT5_4Nano,
		},
		{
			name:     "custom model returns as-is",
			input:    "custom-model",
			expected: "custom-model",
		},
		{
			name:     "empty string returns as-is",
			input:    "",
			expected: "",
		},
		{
			name:     "ollama model",
			input:    "llama3:latest",
			expected: "llama3:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOpenAIModel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewOpenAIClient_WithBasicConfig(t *testing.T) {
	tests := []struct {
		name   string
		config OpenAIConfig
	}{
		{
			name: "gpt-4.1 with API key",
			config: OpenAIConfig{
				Model:  "gpt-4.1",
				APIKey: "test-api-key",
			},
		},
		{
			name: "gpt-4.1-mini with API key",
			config: OpenAIConfig{
				Model:  "gpt-4.1-mini",
				APIKey: "test-api-key",
			},
		},
		{
			name: "custom model with API key",
			config: OpenAIConfig{
				Model:  "custom-model",
				APIKey: "test-api-key",
			},
		},
		{
			name: "empty API key",
			config: OpenAIConfig{
				Model:  "gpt-4.1",
				APIKey: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewOpenAIClient(tt.config)
			require.NoError(t, err)
			assert.NotNil(t, client)

			// Verify wrapper type
			wrapper, ok := client.(*openaiWrapper)
			require.True(t, ok, "client should be openaiWrapper type")
			assert.NotNil(t, wrapper.client)
		})
	}
}

func TestNewOpenAIClient_WithCustomBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{
			name:    "with custom base URL",
			baseURL: "https://api.custom.com/v1",
		},
		{
			name:    "with localhost base URL",
			baseURL: "http://localhost:11434/v1",
		},
		{
			name:    "empty base URL uses default",
			baseURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := OpenAIConfig{
				Model:   "gpt-5.4",
				APIKey:  "test-key",
				BaseURL: tt.baseURL,
			}

			client, err := NewOpenAIClient(config)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestNewOpenAIClient_WithSkipSSL(t *testing.T) {
	tests := []struct {
		name    string
		skipSSL bool
	}{
		{
			name:    "skip SSL enabled",
			skipSSL: true,
		},
		{
			name:    "skip SSL disabled",
			skipSSL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := OpenAIConfig{
				Model:   "gpt-5.4",
				APIKey:  "test-key",
				SkipSSL: tt.skipSSL,
			}

			client, err := NewOpenAIClient(config)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestNewOpenAIClient_WithTokensAndTemperature(t *testing.T) {
	tests := []struct {
		name           string
		maxTokens      int
		temperature    float64
		expectedTokens int
		expectedTemp   float64
	}{
		{
			name:           "custom values",
			maxTokens:      2048,
			temperature:    0.5,
			expectedTokens: 2048,
			expectedTemp:   0.5,
		},
		{
			name:           "zero values use defaults",
			maxTokens:      0,
			temperature:    0,
			expectedTokens: 1024,
			expectedTemp:   0.7,
		},
		{
			name:           "partial custom values",
			maxTokens:      512,
			temperature:    0,
			expectedTokens: 512,
			expectedTemp:   0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := OpenAIConfig{
				Model:       "gpt-5.4",
				APIKey:      "test-key",
				MaxTokens:   tt.maxTokens,
				Temperature: tt.temperature,
			}

			client, err := NewOpenAIClient(config)
			require.NoError(t, err)
			assert.NotNil(t, client)

			wrapper := client.(*openaiWrapper)
			assert.Equal(t, tt.expectedTokens, wrapper.maxTokens)
			assert.InEpsilon(t, tt.expectedTemp, wrapper.temperature, 0.001)
		})
	}
}

func TestNewOpenAIClient_ModelMapping(t *testing.T) {
	tests := []struct {
		modelInput    string
		expectedModel openai.ChatModel
	}{
		{"gpt-5.4", openai.ChatModelGPT5_4},
		{"gpt-5.4-mini", openai.ChatModelGPT5_4Mini},
		{"gpt-5.4-nano", openai.ChatModelGPT5_4Nano},
		{"custom-model", "custom-model"},
		{"llama3:latest", "llama3:latest"},
	}

	for _, tt := range tests {
		t.Run(tt.modelInput, func(t *testing.T) {
			config := OpenAIConfig{
				Model:  tt.modelInput,
				APIKey: "test-key",
			}

			client, err := NewOpenAIClient(config)
			require.NoError(t, err)

			wrapper := client.(*openaiWrapper)
			assert.Equal(t, tt.expectedModel, wrapper.model)
		})
	}
}

func TestOpenAIWrapper_ClientProperties(t *testing.T) {
	config := OpenAIConfig{
		Model:       "gpt-5.4",
		APIKey:      "test-api-key",
		BaseURL:     "https://api.openai.com/v1",
		MaxTokens:   2048,
		Temperature: 0.8,
		SkipSSL:     false,
	}

	client, err := NewOpenAIClient(config)
	require.NoError(t, err)
	require.NotNil(t, client)

	wrapper, ok := client.(*openaiWrapper)
	require.True(t, ok)

	// Verify all properties were set correctly
	assert.NotNil(t, wrapper.client)
	assert.Equal(t, openai.ChatModelGPT5_4, wrapper.model)
	assert.Equal(t, 2048, wrapper.maxTokens)
	assert.InEpsilon(t, 0.8, wrapper.temperature, 0.001)
}

func TestOpenAIModel_Constants(t *testing.T) {
	// Verify model constants are properly defined
	assert.Equal(t, openai.ChatModelGPT5_4, ModelGPT5_4)
	assert.Equal(t, openai.ChatModelGPT5_4Mini, ModelGPT5_4Mini)
	assert.Equal(t, openai.ChatModelGPT5_4Nano, ModelGPT5_4Nano)
	assert.Equal(t, "https://api.openai.com/v1", DefaultOpenAIBaseURL)
}

func TestOpenAIWrapper_ImplementsInterface(t *testing.T) {
	var _ GenAIClient = (*openaiWrapper)(nil)
}

func TestNewOpenAIClient_CompleteConfig(t *testing.T) {
	config := OpenAIConfig{
		Model:       "custom-model",
		APIKey:      "sk-test-key",
		BaseURL:     "http://localhost:11434/v1",
		MaxTokens:   4096,
		Temperature: 0.9,
		SkipSSL:     true,
	}

	client, err := NewOpenAIClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)

	wrapper := client.(*openaiWrapper)
	assert.Equal(t, openai.ChatModel("custom-model"), wrapper.model)
	assert.Equal(t, 4096, wrapper.maxTokens)
	assert.InEpsilon(t, 0.9, wrapper.temperature, 0.001)
}

func TestNewOpenAIClient_AllSupportedModels(t *testing.T) {
	models := []string{
		"gpt-5.4",
		"gpt-5.4-mini",
		"gpt-5.4-nano",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			config := OpenAIConfig{
				Model:  model,
				APIKey: "test-key",
			}
			client, err := NewOpenAIClient(config)
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestNewOpenAIClient_OllamaCompatibility(t *testing.T) {
	// Test Ollama-compatible configuration
	config := OpenAIConfig{
		Model:   "llama3:latest",
		APIKey:  "", // Ollama doesn't require API key
		BaseURL: "http://localhost:11434/v1",
		SkipSSL: false,
	}

	client, err := NewOpenAIClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)

	wrapper := client.(*openaiWrapper)
	assert.Equal(t, openai.ChatModel("llama3:latest"), wrapper.model)
}

func TestNewOpenAIClient_DefaultValues(t *testing.T) {
	config := OpenAIConfig{
		Model:  "gpt-5.4",
		APIKey: "test-key",
	}

	client, err := NewOpenAIClient(config)
	require.NoError(t, err)

	wrapper := client.(*openaiWrapper)

	// Verify defaults
	assert.Equal(t, 1024, wrapper.maxTokens, "should use default maxTokens")
	assert.InEpsilon(t, 0.7, wrapper.temperature, 0.001, "should use default temperature")
}
