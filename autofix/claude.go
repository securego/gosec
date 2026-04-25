package autofix

import (
	"context"
	"errors"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const (
	ModelClaudeOpus4_7   = anthropic.ModelClaudeOpus4_7
	ModelClaudeOpus4_6   = anthropic.ModelClaudeOpus4_6
	ModelClaudeSonnet4_6 = anthropic.ModelClaudeSonnet4_6
	ModelClaudeOpus4_5   = anthropic.ModelClaudeOpus4_5_20251101
	ModelClaudeSonnet4_5 = anthropic.ModelClaudeSonnet4_5_20250929
	ModelClaudeHaiku4_5  = anthropic.ModelClaudeHaiku4_5_20251001
)

var _ GenAIClient = (*claudeWrapper)(nil)

type claudeWrapper struct {
	client anthropic.Client
	model  anthropic.Model
}

func NewClaudeClient(model, apiKey string) (GenAIClient, error) {
	var options []option.RequestOption

	if apiKey != "" {
		options = append(options, option.WithAPIKey(apiKey))
	}

	anthropicModel := parseAnthropicModel(model)

	return &claudeWrapper{
		client: anthropic.NewClient(options...),
		model:  anthropicModel,
	}, nil
}

func (c *claudeWrapper) GenerateSolution(ctx context.Context, prompt string) (string, error) {
	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.model,
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("generating autofix: %w", err)
	}

	if resp == nil || len(resp.Content) == 0 {
		return "", errors.New("no autofix returned by claude")
	}

	if len(resp.Content[0].Text) == 0 {
		return "", errors.New("nothing found in the first autofix returned by claude")
	}

	return resp.Content[0].Text, nil
}

func parseAnthropicModel(model string) anthropic.Model {
	switch model {
	case "claude-opus-4-7":
		return anthropic.ModelClaudeOpus4_7
	case "claude-sonnet-4-6", "claude-sonnet": // Default
		return anthropic.ModelClaudeSonnet4_6
	case "claude-opus-4-6", "claude-opus":
		return anthropic.ModelClaudeOpus4_6
	case "claude-sonnet-4-5", "claude-sonnet-4-5-20250929":
		return anthropic.ModelClaudeSonnet4_5_20250929
	case "claude-opus-4-5", "claude-opus-4-5-20251101":
		return anthropic.ModelClaudeOpus4_5_20251101
	case "claude-haiku-4-5", "claude-haiku-4-5-20251001":
		return anthropic.ModelClaudeHaiku4_5_20251001
	}

	return anthropic.ModelClaudeSonnet4_6
}
