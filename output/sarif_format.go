package output

import (
	"fmt"
	"github.com/securego/gosec/v2"
	"strconv"
	"strings"
)

type sarifLevel string

const (
	sarifNone    = sarifLevel("none")
	sarifNote    = sarifLevel("note")
	sarifWarning = sarifLevel("warning")
	sarifError   = sarifLevel("error")
)

type sarifProperties struct {
	Tags []string `json:"tags"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription *sarifMessage    `json:"shortDescription"`
	FullDescription  *sarifMessage    `json:"fullDescription"`
	Help             *sarifMessage    `json:"help"`
	Properties       *sarifProperties `json:"properties"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   uint64 `json:"startLine"`
	EndLine     uint64 `json:"endLine"`
	StartColumn uint64 `json:"startColumn"`
	EndColumn   uint64 `json:"endColumn"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation *sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     sarifLevel       `json:"level"`
	Message   *sarifMessage    `json:"message"`
	Locations []*sarifLocation `json:"locations"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	InformationURI string       `json:"informationUri"`
	Rules          []*sarifRule `json:"rules,omitempty"`
}

type sarifTool struct {
	Driver *sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    *sarifTool     `json:"tool"`
	Results []*sarifResult `json:"results"`
}

type sarifReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []*sarifRun `json:"runs"`
}

// buildSarifReport return SARIF report struct
func buildSarifReport() *sarifReport {
	return &sarifReport{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
		Runs:    []*sarifRun{},
	}
}

// buildSarifRule return SARIF rule field struct
func buildSarifRule(issue *gosec.Issue) *sarifRule {
	return &sarifRule{
		ID:   fmt.Sprintf("%s (CWE-%s)", issue.RuleID, issue.Cwe.ID),
		Name: issue.What,
		ShortDescription: &sarifMessage{
			Text: issue.What,
		},
		FullDescription: &sarifMessage{
			Text: issue.What,
		},
		Help: &sarifMessage{
			Text: fmt.Sprintf("%s\nSeverity: %s\nConfidence: %s\nCWE: %s", issue.What, issue.Severity.String(), issue.Confidence.String(), issue.Cwe.URL),
		},
		Properties: &sarifProperties{
			Tags: []string{fmt.Sprintf("CWE-%s", issue.Cwe.ID), issue.Severity.String()},
		},
	}
}

// buildSarifLocation return SARIF location struct
func buildSarifLocation(issue *gosec.Issue, rootPaths []string) (*sarifLocation, error) {
	var filePath string

	lines := strings.Split(issue.Line, "-")
	startLine, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return nil, err
	}
	endLine := startLine
	if len(lines) > 1 {
		endLine, err = strconv.ParseUint(lines[1], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	col, err := strconv.ParseUint(issue.Col, 10, 64)
	if err != nil {
		return nil, err
	}

	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			filePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}

	location := &sarifLocation{
		PhysicalLocation: &sarifPhysicalLocation{
			ArtifactLocation: &sarifArtifactLocation{
				URI: filePath,
			},
			Region: &sarifRegion{
				StartLine:   startLine,
				EndLine:     endLine,
				StartColumn: col,
				EndColumn:   col,
			},
		},
	}

	return location, nil
}
