package autofix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genai"
)

func TestParseGeminiModel_AllModels(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  GenAIModel
		expectErr bool
	}{
		{
			name:      "gemini-3.1-pro-preview",
			input:     "gemini-3.1-pro-preview",
			expected:  ModelGeminiPro3_1,
			expectErr: false,
		},
		{
			name:      "gemini-2.5-pro",
			input:     "gemini-2.5-pro",
			expected:  ModelGeminiPro2_5,
			expectErr: false,
		},
		{
			name:      "gemini-2.5-flash",
			input:     "gemini-2.5-flash",
			expected:  ModelGeminiFlash2_5,
			expectErr: false,
		},
		{
			name:      "gemini-2.5-flash-lite",
			input:     "gemini-2.5-flash-lite",
			expected:  ModelGeminiFlash2_5Lite,
			expectErr: false,
		},
		{
			name:      "gemini default",
			input:     "gemini",
			expected:  ModelGeminiPro3_1,
			expectErr: false,
		},
		{
			name:      "shut down gemini-3-pro-preview",
			input:     "gemini-3-pro-preview",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "unsupported model",
			input:     "gemini-unknown",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "empty model",
			input:     "",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "invalid prefix",
			input:     "gpt-4o",
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseGeminiModel(tt.input)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported gemini model")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNewGeminiClient_WithModel(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		apiKey    string
		expectErr bool
	}{
		{
			name:      "valid model gemini-2.5-pro",
			model:     "gemini-2.5-pro",
			apiKey:    "test-api-key",
			expectErr: false,
		},
		{
			name:      "valid model gemini-2.0-flash",
			model:     "gemini-2.5-flash",
			apiKey:    "test-api-key",
			expectErr: false,
		},
		{
			name:      "default gemini model",
			model:     "gemini",
			apiKey:    "test-api-key",
			expectErr: false,
		},
		{
			name:      "unsupported model",
			model:     "invalid-model",
			apiKey:    "test-api-key",
			expectErr: true,
		},
		{
			name:      "empty API key",
			model:     "gemini-2.5-flash",
			apiKey:    "",
			expectErr: true, // Gemini requires API key at client creation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewGeminiClient(tt.model, tt.apiKey)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)

				// Verify wrapper type
				wrapper, ok := client.(*geminiWrapper)
				require.True(t, ok, "client should be geminiWrapper type")
				assert.NotNil(t, wrapper.client)
			}
		})
	}
}

func TestNewGeminiClient_ModelMapping(t *testing.T) {
	tests := []struct {
		modelInput    string
		expectedModel GenAIModel
	}{
		{"gemini-3.1-pro-preview", ModelGeminiPro3_1},
		{"gemini-2.5-pro", ModelGeminiPro2_5},
		{"gemini-2.5-flash", ModelGeminiFlash2_5},
		{"gemini-2.5-flash-lite", ModelGeminiFlash2_5Lite},
		{"gemini", ModelGeminiPro3_1}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.modelInput, func(t *testing.T) {
			client, err := NewGeminiClient(tt.modelInput, "test-key")
			require.NoError(t, err)

			wrapper := client.(*geminiWrapper)
			assert.Equal(t, tt.expectedModel, wrapper.model)
		})
	}
}

func TestGeminiWrapper_ClientProperties(t *testing.T) {
	client, err := NewGeminiClient("gemini-2.5-flash", "test-api-key")
	require.NoError(t, err)
	require.NotNil(t, client)

	wrapper, ok := client.(*geminiWrapper)
	require.True(t, ok)

	// Verify client was initialized
	assert.NotNil(t, wrapper.client)
	assert.Equal(t, ModelGeminiFlash2_5, wrapper.model)
}

func TestGeminiModel_Constants(t *testing.T) {
	// Verify model constants are properly defined
	assert.Equal(t, ModelGeminiPro3_1, GenAIModel("gemini-3.1-pro-preview"))
	assert.Equal(t, ModelGeminiPro2_5, GenAIModel("gemini-2.5-pro"))
	assert.Equal(t, ModelGeminiFlash2_5, GenAIModel("gemini-2.5-flash"))
	assert.Equal(t, ModelGeminiFlash2_5Lite, GenAIModel("gemini-2.5-flash-lite"))
}

func TestGeminiGenerateSolution_CandidateWithoutContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A candidate blocked by the safety filter has a finishReason and no content.
		_, _ = w.Write([]byte(`{"candidates":[{"finishReason":"SAFETY","index":0}]}`))
	}))
	defer server.Close()

	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:      "test-key",
		Backend:     genai.BackendGeminiAPI,
		HTTPOptions: genai.HTTPOptions{BaseURL: server.URL},
	})
	require.NoError(t, err)

	wrapper := &geminiWrapper{client: client, model: ModelGeminiPro3_1}

	require.NotPanics(t, func() {
		_, err = wrapper.GenerateSolution(context.Background(), "fix this")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gemini")
}
