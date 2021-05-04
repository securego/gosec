package output

import (
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/sonar"
	"strconv"
	"strings"
)

const (
	//SonarqubeEffortMinutes effort to fix in minutes
	SonarqubeEffortMinutes = 5
)

func convertToSonarIssues(rootPaths []string, data *reportInfo) (*sonar.Report, error) {
	si := &sonar.Report{Issues: []*sonar.Issue{}}
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

		s := &sonar.Issue{
			EngineID:        "gosec",
			RuleID:          issue.RuleID,
			PrimaryLocation: primaryLocation,
			Type:            "VULNERABILITY",
			Severity:        severity,
			EffortMinutes:   SonarqubeEffortMinutes,
		}
		si.Issues = append(si.Issues, s)
	}
	return si, nil
}

func buildPrimaryLocation(message string, filePath string, textRange *sonar.TextRange) *sonar.Location {
	return &sonar.Location{
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

func parseTextRange(issue *gosec.Issue) (*sonar.TextRange, error) {
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
	return &sonar.TextRange{StartLine: startLine, EndLine: endLine}, nil
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
