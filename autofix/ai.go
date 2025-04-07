package autofix

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"

	"github.com/securego/gosec/v2/issue"
)

const (
	GeminiModel = "gemini-1.5-flash"
	AIPrompt    = `Provide a brief explanation and a solution to fix this security issue
  in Go programming language: %q.
  Answer in markdown format and keep the response limited to 200 words.`
	GeminiProvider = "gemini"

	timeout = 30 * time.Second
)

// GenAIClient defines the interface for the GenAI client.
type GenAIClient interface {
	// Close clean up and close the client.
	Close() error
	// GenerativeModel build the generative mode.
	GenerativeModel(name string) GenAIGenerativeModel
}

// GenAIGenerativeModel defines the interface for the Generative Model.
type GenAIGenerativeModel interface {
	// GenerateContent generates an response for given prompt.
	GenerateContent(ctx context.Context, prompt string) (string, error)
}

// genAIClientWrapper wraps the genai.Client to implement GenAIClient.
type genAIClientWrapper struct {
	client *genai.Client
}

// Close closes the gen AI client.
func (w *genAIClientWrapper) Close() error {
	return w.client.Close()
}

// GenerativeModel builds the generative Model.
func (w *genAIClientWrapper) GenerativeModel(name string) GenAIGenerativeModel {
	return &genAIGenerativeModelWrapper{model: w.client.GenerativeModel(name)}
}

// genAIGenerativeModelWrapper wraps the genai.GenerativeModel to implement GenAIGenerativeModel
type genAIGenerativeModelWrapper struct {
	// model is the underlying generative model
	model *genai.GenerativeModel
}

// GenerateContent generates a response for the given prompt using gemini API.
func (w *genAIGenerativeModelWrapper) GenerateContent(ctx context.Context, prompt string) (string, error) {
	resp, err := w.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", fmt.Errorf("generating autofix: %w", err)
	}
	if len(resp.Candidates) == 0 {
		return "", errors.New("no autofix returned by gemini")
	}

	if len(resp.Candidates[0].Content.Parts) == 0 {
		return "", errors.New("nothing found in the first autofix returned by gemini")
	}

	// Return the first candidate
	return fmt.Sprintf("%+v", resp.Candidates[0].Content.Parts[0]), nil
}

// NewGenAIClient creates a new gemini API client.
func NewGenAIClient(ctx context.Context, aiAPIKey, endpoint string) (GenAIClient, error) {
	clientOptions := []option.ClientOption{option.WithAPIKey(aiAPIKey)}
	if endpoint != "" {
		clientOptions = append(clientOptions, option.WithEndpoint(endpoint))
	}

	client, err := genai.NewClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("calling gemini API: %w", err)
	}

	return &genAIClientWrapper{client: client}, nil
}

func generateSolutionByGemini(client GenAIClient, issues []*issue.Issue) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	model := client.GenerativeModel(GeminiModel)
	cachedAutofix := make(map[string]string)
	for _, issue := range issues {
		if val, ok := cachedAutofix[issue.What]; ok {
			issue.Autofix = val
			continue
		}

		prompt := fmt.Sprintf(AIPrompt, issue.What)
		resp, err := model.GenerateContent(ctx, prompt)
		if err != nil {
			return fmt.Errorf("generating autofix with gemini: %w", err)
		}

		if resp == "" {
			return errors.New("no autofix returned by gemini")
		}

		issue.Autofix = resp
		cachedAutofix[issue.What] = issue.Autofix
	}
	return nil
}

// GenerateSolution generates a solution for the given issues using the specified AI provider
func GenerateSolution(aiAPIProvider, aiAPIKey, endpoint string, issues []*issue.Issue) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var client GenAIClient

	switch aiAPIProvider {
	case GeminiProvider:
		var err error
		client, err = NewGenAIClient(ctx, aiAPIKey, endpoint)
		if err != nil {
			return fmt.Errorf("generating autofix: %w", err)
		}
	default:
		return errors.New("ai provider not supported")
	}

	defer client.Close()

	return generateSolutionByGemini(client, issues)
}
