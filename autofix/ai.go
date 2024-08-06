package autofix

import (
	"context"
	"fmt"
	"time"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"

	"github.com/securego/gosec/v2/issue"
)

const (
	GeminiModel    = "gemini-1.5-flash"
	AIPrompt       = "In golang, what is the solution to fix the error \"%s\". Answer limited to 200 words"
	GeminiProvider = "gemini"

	timeout = 30 * time.Second
)

// GenAIClient defines the interface for the GenAI client
type GenAIClient interface {
	Close() error
	GenerativeModel(name string) GenAIGenerativeModel
}

// GenAIGenerativeModel defines the interface for the Generative Model
type GenAIGenerativeModel interface {
	GenerateContent(ctx context.Context, prompt string) (string, error)
}

// genAIClientWrapper wraps the genai.Client to implement GenAIClient
type genAIClientWrapper struct {
	client *genai.Client
}

func (w *genAIClientWrapper) Close() error {
	return w.client.Close()
}

func (w *genAIClientWrapper) GenerativeModel(name string) GenAIGenerativeModel {
	return &genAIGenerativeModelWrapper{model: w.client.GenerativeModel(name)}
}

// genAIGenerativeModelWrapper wraps the genai.GenerativeModel to implement GenAIGenerativeModel
type genAIGenerativeModelWrapper struct {
	model *genai.GenerativeModel
}

func (w *genAIGenerativeModelWrapper) GenerateContent(ctx context.Context, prompt string) (string, error) {
	resp, err := w.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", fmt.Errorf("generate content error: %w", err)
	}
	if len(resp.Candidates) == 0 {
		return "", fmt.Errorf("no candidates found")
	}
	return fmt.Sprintf("%+v", resp.Candidates[0].Content.Parts[0]), nil
}

func NewGenAIClient(ctx context.Context, aiApiKey, endpoint string) (GenAIClient, error) {
	clientOptions := []option.ClientOption{option.WithAPIKey(aiApiKey)}
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
			return fmt.Errorf("gemini generating content: %w", err)
		}

		if resp == "" {
			return errors.New("gemini no candidates found")
		}

		issue.Autofix = resp
		cachedAutofix[issue.What] = issue.Autofix
	}
	return nil
}

// GenerateSolution generates a solution for the given issues using the specified AI provider
func GenerateSolution(aiApiProvider, aiApiKey, endpoint string, issues []*issue.Issue) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var client GenAIClient
	var err error

	switch aiApiProvider {
	case GeminiProvider:
		client, err = NewGenAIClient(ctx, aiApiKey, endpoint)
	default:
		return fmt.Errorf("ai provider not supported")
	}

	if err != nil {
		return fmt.Errorf("generate solution error: %w", err)
	}
	defer client.Close()

	return generateSolutionByGemini(client, issues)
}
