package output

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/sarif"
)

type sarifLevel string

const (
	sarifNone    = sarifLevel("none")
	sarifNote    = sarifLevel("note")
	sarifWarning = sarifLevel("warning")
	sarifError   = sarifLevel("error")
)

// buildSarifReport return SARIF report struct
func buildSarifReport() *sarif.StaticAnalysisResultsFormatSARIFVersion210JSONSchema {
	return &sarif.StaticAnalysisResultsFormatSARIFVersion210JSONSchema{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []*sarif.Run{},
	}
}

// buildSarifRule return SARIF rule field struct
func buildSarifRule(issue *gosec.Issue) *sarif.ReportingDescriptor {
	return &sarif.ReportingDescriptor{
		Id:   fmt.Sprintf("%s (CWE-%s)", issue.RuleID, issue.Cwe.ID),
		Name: issue.What,
		ShortDescription: &sarif.MultiformatMessageString{
			Text: issue.What,
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: issue.What,
		},
		Help: &sarif.MultiformatMessageString{
			Text: fmt.Sprintf("%s\nSeverity: %s\nConfidence: %s\nCWE: %s", issue.What, issue.Severity.String(), issue.Confidence.String(), issue.Cwe.URL),
		},
		Properties: &sarif.PropertyBag{
			Tags: []string{fmt.Sprintf("CWE-%s", issue.Cwe.ID), issue.Severity.String()},
		},
		DefaultConfiguration: &sarif.ReportingConfiguration{
			Level: getSarifLevel(issue.Severity.String()),
		},
		Relationships: []*sarif.ReportingDescriptorRelationship{
			{
				Target: &sarif.ReportingDescriptorReference{
					Id: issue.Cwe.ID,
					ToolComponent: &sarif.ToolComponentReference{
						Name: "CWE",
					},
				},
			},
		},
	}
}

func buildSarifTool(driver *sarif.ToolComponent) *sarif.Tool {
	return &sarif.Tool{
		Driver: driver,
	}
}

func buildSarifTaxonomies(taxa []*sarif.ReportingDescriptor) []*sarif.ToolComponent {
	return []*sarif.ToolComponent{
		{Name: "CWE",
			Organization: "MITRE",
			ShortDescription: &sarif.MultiformatMessageString{
				Text: "The MITRE Common Weakness Enumeration",
			},
			Taxa: taxa,
		},
	}
}

func buildSarifTaxum(cwse gosec.Cwe) *sarif.ReportingDescriptor {
	return &sarif.ReportingDescriptor{
		Id:      cwse.ID,
		Name:    cwse.Name,
		HelpUri: cwse.URL,
	}
}

func buildSarifDriver(rules []*sarif.ReportingDescriptor) *sarif.ToolComponent {
	return &sarif.ToolComponent{
		Name:    "gosec",
		Version: "2.1.0",
		SupportedTaxonomies: []*sarif.ToolComponentReference{
			{Name: "CWE"},
		},
		InformationUri: "https://github.com/securego/gosec/",
		Rules:          rules,
	}
}

func buildSarifRun(results []*sarif.Result, taxonomies []*sarif.ToolComponent, tool *sarif.Tool) *sarif.Run {
	return &sarif.Run{
		Results:    results,
		Taxonomies: taxonomies,
		Tool:       tool,
	}
}

// buildSarifLocation return SARIF location struct
func buildSarifLocation(issue *gosec.Issue, rootPaths []string) (*sarif.Location, error) {
	var filePath string

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

	col, err := strconv.Atoi(issue.Col)
	if err != nil {
		return nil, err
	}

	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			filePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}

	return &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{
				Uri: filePath,
			},
			Region: &sarif.Region{
				StartLine:   startLine,
				EndLine:     endLine,
				StartColumn: col,
				EndColumn:   col,
			},
		},
	}, nil

}

// From https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127839
// * "warning": The rule specified by ruleId was evaluated and a problem was found.
// * "error": The rule specified by ruleId was evaluated and a serious problem was found.
// * "note": The rule specified by ruleId was evaluated and a minor problem or an opportunity to improve the code was found.
func getSarifLevel(s string) sarifLevel {
	switch s {
	case "LOW":
		return sarifWarning
	case "MEDIUM":
		return sarifError
	case "HIGH":
		return sarifError
	default:
		return sarifNote
	}
}
