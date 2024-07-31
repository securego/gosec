package proposesolution

import (
	"context"
	"fmt"
	"log"

	"github.com/google/generative-ai-go/genai"
	"github.com/securego/gosec/v2/issue"
	"google.golang.org/api/option"
)

func GetSolutionFromGemini(apiKey string, issues []*issue.Issue) {
	if len(issues) == 0 || apiKey == "" {
		log.Printf("No issues to solve OR API key is empty")
		return
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-1.5-flash")
	for _, issue := range issues {
		prompt := fmt.Sprintf("What is the solution to fix the error \"%s\". Answer limited to 200 words", issue.What)
		resp, err := model.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			log.Fatal(err)
		}

		issue.ProposedSolution = fmt.Sprintf("%+v", resp.Candidates[0].Content.Parts[0])
	}
}
