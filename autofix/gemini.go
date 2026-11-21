package autofix

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genai"
)

// https://ai.google.dev/gemini-api/docs/models
type GenAIModel string

const (
	ModelGeminiPro3_1       GenAIModel = "gemini-3.1-pro-preview"
	ModelGeminiPro2_5       GenAIModel = "gemini-2.5-pro"
	ModelGeminiFlash2_5     GenAIModel = "gemini-2.5-flash"
	ModelGeminiFlash2_5Lite GenAIModel = "gemini-2.5-flash-lite"
)

var _ GenAIClient = (*geminiWrapper)(nil)

type geminiWrapper struct {
	client *genai.Client
	model  GenAIModel
}

func NewGeminiClient(model, apiKey string) (GenAIClient, error) {
	ctx := context.Background()

	genaiModel, err := parseGeminiModel(model)
	if err != nil {
		return nil, err
	}

	config := genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendUnspecified,
	}

	client, err := genai.NewClient(ctx, &config)
	if err != nil {
		return nil, fmt.Errorf("creating gemini client: %w", err)
	}

	return &geminiWrapper{
		client: client,
		model:  genaiModel,
	}, nil
}

func (g *geminiWrapper) GenerateSolution(ctx context.Context, prompt string) (string, error) {
	var config genai.GenerateContentConfig

	resp, err := g.client.Models.GenerateContent(ctx, string(g.model), genai.Text(prompt), &config)
	if err != nil {
		return "", fmt.Errorf("generating autofix: %w", err)
	}

	if resp == nil || len(resp.Candidates) == 0 {
		return "", errors.New("no autofix returned by gemini")
	}

	if resp.Candidates[0].Content == nil || len(resp.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("nothing found in the first autofix returned by gemini")
	}

	return resp.Text(), nil
}

func parseGeminiModel(model string) (GenAIModel, error) {
	switch model {
	case "gemini-3.1-pro-preview", "gemini": // Default
		return ModelGeminiPro3_1, nil
	case "gemini-2.5-pro":
		return ModelGeminiPro2_5, nil
	case "gemini-2.5-flash":
		return ModelGeminiFlash2_5, nil
	case "gemini-2.5-flash-lite":
		return ModelGeminiFlash2_5Lite, nil
	}

	// gemini-3-pro-preview was shut down by Google; keep rejecting it with a
	// clear error rather than sending a request that is guaranteed to fail.
	if model == "gemini-3-pro-preview" {
		return "", fmt.Errorf("unsupported gemini model: %s", model)
	}

	// Pass any other gemini-* model ID through to the API instead of rejecting
	// it, so newer models work without a code change.
	if strings.HasPrefix(model, "gemini-") {
		return GenAIModel(model), nil
	}

	return "", fmt.Errorf("unsupported gemini model: %s", model)
}
