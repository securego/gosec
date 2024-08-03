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
	AIPrompt       = "What is the solution to fix the error \"%s\". Answer limited to 200 words"
	GeminiProvider = "gemini"
)

func generateSolutionByGemini(aiApiKey string, issues []*issue.Issue) error {
	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := genai.NewClient(ctx, option.WithAPIKey(aiApiKey))
	if err != nil {
		return fmt.Errorf("calling gemeni API: %w", err)
	}
	defer client.Close()

	model := client.GenerativeModel(GeminiModel)
	cachedAutofix := make(map[string]string)
	for _, issue := range issues {
		if val, ok := cachedAutofix[issue.What]; ok {
			issue.Autofix = val
			continue
		}

		prompt := fmt.Sprintf(AIPrompt, issue.What)
		resp, err := model.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			return fmt.Errorf("gemini generating content: %w", err)
		}

		if len(resp.Candidates) == 0 {
			return fmt.Errorf("gemini no candidates found")
		}

		issue.Autofix = fmt.Sprintf("%+v", resp.Candidates[0].Content.Parts[0])
		cachedAutofix[issue.What] = issue.Autofix
	}
	return nil
}

// GenerateSolution generates a solution for the given issues using the specified AI provider
func GenerateSolution(aiApiProvider, aiApiKey string, issues []*issue.Issue) error {
	switch aiApiProvider {
	case GeminiProvider:
		return generateSolutionByGemini(aiApiKey, issues)
	default:
		return fmt.Errorf("ai provider not supported")
	}
}
