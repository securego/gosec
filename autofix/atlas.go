package autofix

import "strings"

const (
	ModelAtlasDefault         = "deepseek-ai/deepseek-v4-flash"
	ModelAtlasDeepSeekV4Flash = "deepseek-ai/deepseek-v4-flash"
	ModelAtlasQwenCoderNext   = "qwen/qwen3-coder-next"
	ModelAtlasKimiK26         = "moonshotai/kimi-k2.6"

	DefaultAtlasBaseURL = "https://api.atlascloud.ai/v1"
)

type AtlasConfig struct {
	Model       string
	APIKey      string `json:"-"`
	BaseURL     string
	MaxTokens   int
	Temperature float64
	SkipSSL     bool
}

func NewAtlasClient(config AtlasConfig) (GenAIClient, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = DefaultAtlasBaseURL
	}

	return NewOpenAIClient(OpenAIConfig{
		Model:       parseAtlasModel(config.Model),
		APIKey:      config.APIKey,
		BaseURL:     baseURL,
		MaxTokens:   config.MaxTokens,
		Temperature: config.Temperature,
		SkipSSL:     config.SkipSSL,
	})
}

func parseAtlasModel(model string) string {
	switch model {
	case "", "atlas", "atlas-deepseek-v4-flash":
		return ModelAtlasDefault
	case "atlas-qwen3-coder-next", "atlas-qwen-turbo":
		return ModelAtlasQwenCoderNext
	case "atlas-kimi-k2.6", "atlas-kimi-k2":
		return ModelAtlasKimiK26
	}

	for _, prefix := range []string{"atlas/", "atlas:"} {
		if strings.HasPrefix(model, prefix) {
			trimmed := strings.TrimPrefix(model, prefix)
			if trimmed != "" {
				return trimmed
			}
			return ModelAtlasDefault
		}
	}

	if strings.HasPrefix(model, "atlas-") {
		trimmed := strings.TrimPrefix(model, "atlas-")
		if trimmed != "" {
			return trimmed
		}
		return ModelAtlasDefault
	}

	return model
}
