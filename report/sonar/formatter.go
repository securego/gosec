package sonar

import (
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/report/core"
	"strconv"
	"strings"
)

const (
	//EffortMinutes effort to fix in minutes
	EffortMinutes = 5
)

//GenerateReport Convert a gosec report to a Sonar Report
func GenerateReport(rootPaths []string, data *core.ReportInfo) (*Report, error) {
	si := &Report{Issues: []*Issue{}}
	for _, issue := range data.Issues {
		sonarFilePath := parseFilePath(issue, rootPaths)

		if sonarFilePath == "" {
			continue
		}

		textRange, err := parseTextRange(issue)
		if err != nil {
			return si, err
		}

		primaryLocation := buildPrimaryLocation(issue.What, sonarFilePath, textRange)
		severity := getSonarSeverity(issue.Severity.String())

		s := &Issue{
			EngineID:        "gosec",
			RuleID:          issue.RuleID,
			PrimaryLocation: primaryLocation,
			Type:            "VULNERABILITY",
			Severity:        severity,
			EffortMinutes:   EffortMinutes,
		}
		si.Issues = append(si.Issues, s)
	}
	return si, nil
}

func buildPrimaryLocation(message string, filePath string, textRange *TextRange) *Location {
	return &Location{
		Message:   message,
		FilePath:  filePath,
		TextRange: textRange,
	}
}

func parseFilePath(issue *gosec.Issue, rootPaths []string) string {
	var sonarFilePath string
	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			sonarFilePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}
	return sonarFilePath
}

func parseTextRange(issue *gosec.Issue) (*TextRange, error) {
	lines := strings.Split(issue.Line, "-")
	startLine, err := strconv.Atoi(lines[0])
	if err != nil {
		return nil, err
	}
	endLine := startLine
	if len(lines) > 1 {
		endLine, err = strconv.Atoi(lines[1])
		if err != nil {
			return nil, err
		}
	}
	return &TextRange{StartLine: startLine, EndLine: endLine}, nil
}

func getSonarSeverity(s string) string {
	switch s {
	case "LOW":
		return "MINOR"
	case "MEDIUM":
		return "MAJOR"
	case "HIGH":
		return "BLOCKER"
	default:
		return "INFO"
	}
}
