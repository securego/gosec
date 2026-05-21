package autofix

import "strings"

const (
	modelAtlasDefault         = "deepseek-ai/deepseek-v4-flash"
	modelAtlasDeepSeekV4Flash = "deepseek-ai/deepseek-v4-flash"
	modelAtlasQwenCoderNext   = "qwen/qwen3-coder-next"
	modelAtlasKimiK26         = "moonshotai/kimi-k2.6"

	defaultAtlasBaseURL = "https://api.atlascloud.ai/v1"
)

type atlasConfig struct {
	Model       string
	APIKey      string `json:"-"`
	BaseURL     string
	MaxTokens   int
	Temperature float64
	SkipSSL     bool
}

func newAtlasClient(config atlasConfig) (GenAIClient, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultAtlasBaseURL
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
		return modelAtlasDefault
	case "atlas-qwen3-coder-next", "atlas-qwen-turbo":
		return modelAtlasQwenCoderNext
	case "atlas-kimi-k2.6", "atlas-kimi-k2":
		return modelAtlasKimiK26
	}

	for _, prefix := range []string{"atlas/", "atlas:"} {
		if strings.HasPrefix(model, prefix) {
			trimmed := strings.TrimPrefix(model, prefix)
			if trimmed != "" {
				return trimmed
			}
			return modelAtlasDefault
		}
	}

	if strings.HasPrefix(model, "atlas-") {
		trimmed := strings.TrimPrefix(model, "atlas-")
		if trimmed != "" {
			return trimmed
		}
		return modelAtlasDefault
	}

	return model
}
