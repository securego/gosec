package autofix

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// A LiteLLM proxy (https://docs.litellm.ai/docs/simple_proxy) serves one
// OpenAI-compatible endpoint in front of many providers: OpenAI, Anthropic,
// Gemini, Bedrock, Vertex AI, Azure, Ollama and more. Its model names are the
// aliases configured on the proxy, so they can look like any provider's
// (claude-sonnet-4-6, gemini-2.5-flash). The litellm prefix sends them to the
// proxy instead of the native Claude or Gemini client.

const defaultLiteLLMBaseURL = "http://localhost:4000"

var _ GenAIClient = (*liteLLMWrapper)(nil)

type liteLLMConfig struct {
	Model      string
	APIKey     string `json:"-"`
	BaseURL    string
	SkipSSL    bool
	HTTPClient *http.Client
}

type liteLLMWrapper struct {
	client openai.Client
	model  string
}

func isLiteLLMModel(model string) bool {
	return model == "litellm" || strings.HasPrefix(model, "litellm/") || strings.HasPrefix(model, "litellm:")
}

// parseLiteLLMModel returns the proxy model name from litellm, litellm/<model>
// or litellm:<model>. An empty name means: use a model the proxy lists.
func parseLiteLLMModel(model string) string {
	for _, prefix := range []string{"litellm/", "litellm:"} {
		if strings.HasPrefix(model, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(model, prefix))
		}
	}
	return ""
}

func newLiteLLMClient(ctx context.Context, config liteLLMConfig) (GenAIClient, error) {
	baseURL := liteLLMBaseURL(config.BaseURL)

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = newLiteLLMHTTPClient(config.SkipSSL)
	}

	// Check the model against the proxy once, before any issue is sent: a
	// misspelt alias or a rejected key then fails here, not once per issue.
	models, err := listLiteLLMModels(ctx, httpClient, baseURL, config.APIKey)
	if err != nil {
		return nil, err
	}

	model := parseLiteLLMModel(config.Model)
	switch {
	case model == "" && len(models) == 0:
		return nil, fmt.Errorf("litellm proxy at %s lists no models; set one with litellm/<model>", baseURL)
	case model == "":
		model = models[0]
	case len(models) > 0 && !slices.Contains(models, model):
		return nil, fmt.Errorf("model %q is not served by the litellm proxy at %s; available models: %s",
			model, baseURL, strings.Join(models, ", "))
	}

	options := []option.RequestOption{
		option.WithBaseURL(baseURL + "/"),
		option.WithHTTPClient(httpClient),
		// The proxy drops parameters the routed model does not accept instead
		// of failing the request.
		option.WithJSONSet("drop_params", true),
	}
	if config.APIKey != "" {
		options = append(options, option.WithAPIKey(config.APIKey))
	}

	return &liteLLMWrapper{
		client: openai.NewClient(options...),
		model:  model,
	}, nil
}

// newLiteLLMHTTPClient keeps the default transport (proxy environment, dial
// and TLS timeouts) and only turns off certificate checks when asked to.
func newLiteLLMHTTPClient(skipSSL bool) *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{}
	}
	transport = transport.Clone()
	if skipSSL {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402
		}
	}
	return &http.Client{Transport: transport}
}

type liteLLMModelList struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// listLiteLLMModels returns the model names the proxy serves (GET /v1/models),
// in the proxy's order.
func listLiteLLMModels(ctx context.Context, httpClient *http.Client, baseURL, apiKey string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("invalid litellm base URL %q: %w", baseURL, err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing litellm models: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("listing litellm models: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing litellm models: %s: %s", resp.Status, liteLLMErrorMessage(body))
	}

	var list liteLLMModelList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("listing litellm models: %w", err)
	}

	models := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		if m.ID != "" && !slices.Contains(models, m.ID) {
			models = append(models, m.ID)
		}
	}
	return models, nil
}

// liteLLMBaseURL returns the proxy's /v1 endpoint, from either the proxy root
// or its /v1 path; the default is a proxy on localhost.
func liteLLMBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = defaultLiteLLMBaseURL
	}
	if !strings.HasSuffix(baseURL, "/v1") {
		baseURL += "/v1"
	}
	return baseURL
}

// liteLLMErrorMessage returns the proxy's {"error": {"message": ...}} text, or
// the start of the body when it has another shape.
func liteLLMErrorMessage(body []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

func (l *liteLLMWrapper) GenerateSolution(ctx context.Context, prompt string) (string, error) {
	resp, err := l.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model: l.model,
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		},
	})
	if err != nil {
		var apiErr *openai.Error
		if errors.As(err, &apiErr) {
			return "", fmt.Errorf("generating autofix with litellm model %q: %d %s", l.model, apiErr.StatusCode, apiErr.Message)
		}
		return "", fmt.Errorf("generating autofix with litellm model %q: %w", l.model, err)
	}

	if resp == nil || len(resp.Choices) == 0 {
		return "", errors.New("no autofix returned by litellm")
	}

	content := strings.TrimSpace(resp.Choices[0].Message.Content)
	if content == "" {
		if resp.Choices[0].FinishReason == "length" {
			return "", fmt.Errorf("litellm model %q hit its output limit before answering", l.model)
		}
		return "", errors.New("nothing found in the first autofix returned by litellm")
	}

	return content, nil
}
