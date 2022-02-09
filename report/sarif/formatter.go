package sarif

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/cwe"
)

// GenerateReport Convert a gosec report to a Sarif Report
func GenerateReport(rootPaths []string, data *gosec.ReportInfo) (*Report, error) {
	type rule struct {
		index int
		rule  *ReportingDescriptor
	}

	rules := make([]*ReportingDescriptor, 0)
	rulesIndices := make(map[string]rule)
	lastRuleIndex := -1

	results := []*Result{}
	cweTaxa := make([]*ReportingDescriptor, 0)
	weaknesses := make(map[string]*cwe.Weakness)

	for _, issue := range data.Issues {
		_, ok := weaknesses[issue.Cwe.ID]
		if !ok {
			weakness := cwe.Get(issue.Cwe.ID)
			weaknesses[issue.Cwe.ID] = weakness
			cweTaxon := parseSarifTaxon(weakness)
			cweTaxa = append(cweTaxa, cweTaxon)
		}

		r, ok := rulesIndices[issue.RuleID]
		if !ok {
			lastRuleIndex++
			r = rule{index: lastRuleIndex, rule: parseSarifRule(issue)}
			rulesIndices[issue.RuleID] = r
			rules = append(rules, r.rule)
		}

		location, err := parseSarifLocation(issue, rootPaths)
		if err != nil {
			return nil, err
		}

		result := NewResult(r.rule.ID, r.index, getSarifLevel(issue.Severity.String()), issue.What, buildSarifSuppressions(issue.Suppressions)).
			WithLocations(location)

		results = append(results, result)
	}

	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	sort.SliceStable(cweTaxa, func(i, j int) bool { return cweTaxa[i].ID < cweTaxa[j].ID })

	tool := NewTool(buildSarifDriver(rules, data.GosecVersion))

	cweTaxonomy := buildCWETaxonomy(cweTaxa)

	run := NewRun(tool).
		WithTaxonomies(cweTaxonomy).
		WithResults(results...)

	return NewReport(Version, Schema).
		WithRuns(run), nil
}

// parseSarifRule return SARIF rule field struct
func parseSarifRule(issue *gosec.Issue) *ReportingDescriptor {
	cwe := gosec.GetCweByRule(issue.RuleID)
	name := issue.RuleID
	if cwe != nil {
		name = cwe.Name
	}
	return &ReportingDescriptor{
		ID:               issue.RuleID,
		Name:             name,
		ShortDescription: NewMultiformatMessageString(issue.What),
		FullDescription:  NewMultiformatMessageString(issue.What),
		Help: NewMultiformatMessageString(fmt.Sprintf("%s\nSeverity: %s\nConfidence: %s\n",
			issue.What, issue.Severity.String(), issue.Confidence.String())),
		Properties: &PropertyBag{
			"tags":      []string{"security", issue.Severity.String()},
			"precision": strings.ToLower(issue.Confidence.String()),
		},
		DefaultConfiguration: &ReportingConfiguration{
			Level: getSarifLevel(issue.Severity.String()),
		},
		Relationships: []*ReportingDescriptorRelationship{
			buildSarifReportingDescriptorRelationship(issue.Cwe),
		},
	}
}

func buildSarifReportingDescriptorRelationship(weakness *cwe.Weakness) *ReportingDescriptorRelationship {
	return &ReportingDescriptorRelationship{
		Target: &ReportingDescriptorReference{
			ID:            weakness.ID,
			GUID:          uuid3(weakness.SprintID()),
			ToolComponent: NewToolComponentReference(cwe.Acronym),
		},
		Kinds: []string{"superset"},
	}
}

func buildCWETaxonomy(taxa []*ReportingDescriptor) *ToolComponent {
	return NewToolComponent(cwe.Acronym, cwe.Version, cwe.InformationURI).
		WithReleaseDateUtc(cwe.ReleaseDateUtc).
		WithDownloadURI(cwe.DownloadURI).
		WithOrganization(cwe.Organization).
		WithShortDescription(NewMultiformatMessageString(cwe.Description)).
		WithIsComprehensive(true).
		WithLanguage("en").
		WithMinimumRequiredLocalizedDataSemanticVersion(cwe.Version).
		WithTaxa(taxa...)
}

func parseSarifTaxon(weakness *cwe.Weakness) *ReportingDescriptor {
	return &ReportingDescriptor{
		ID:               weakness.ID,
		GUID:             uuid3(weakness.SprintID()),
		HelpURI:          weakness.SprintURL(),
		FullDescription:  NewMultiformatMessageString(weakness.Description),
		ShortDescription: NewMultiformatMessageString(weakness.Name),
	}
}

func parseSemanticVersion(version string) string {
	if len(version) == 0 {
		return "devel"
	}
	if strings.HasPrefix(version, "v") {
		return version[1:]
	}
	return version
}

func buildSarifDriver(rules []*ReportingDescriptor, gosecVersion string) *ToolComponent {
	semanticVersion := parseSemanticVersion(gosecVersion)
	return NewToolComponent("gosec", gosecVersion, "https://github.com/securego/gosec/").
		WithSemanticVersion(semanticVersion).
		WithSupportedTaxonomies(NewToolComponentReference(cwe.Acronym)).
		WithRules(rules...)
}

func uuid3(value string) string {
	return uuid.NewMD5(uuid.Nil, []byte(value)).String()
}

// parseSarifLocation return SARIF location struct
func parseSarifLocation(issue *gosec.Issue, rootPaths []string) (*Location, error) {
	region, err := parseSarifRegion(issue)
	if err != nil {
		return nil, err
	}
	artifactLocation := parseSarifArtifactLocation(issue, rootPaths)
	return NewLocation(NewPhysicalLocation(artifactLocation, region)), nil
}

func parseSarifArtifactLocation(issue *gosec.Issue, rootPaths []string) *ArtifactLocation {
	var filePath string
	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			filePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}
	return NewArtifactLocation(filePath)
}

func parseSarifRegion(issue *gosec.Issue) (*Region, error) {
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
	var code string
	line := startLine
	codeLines := strings.Split(issue.Code, "\n")
	for _, codeLine := range codeLines {
		lineStart := fmt.Sprintf("%d:", line)
		if strings.HasPrefix(codeLine, lineStart) {
			code += strings.TrimSpace(
				strings.TrimPrefix(codeLine, lineStart))
			if endLine > startLine {
				code += "\n"
			}
			line++
			if line > endLine {
				break
			}
		}
	}
	snippet := NewArtifactContent(code)
	return NewRegion(startLine, endLine, col, col, "go").WithSnippet(snippet), nil
}

func getSarifLevel(s string) Level {
	switch s {
	case "LOW":
		return Warning
	case "MEDIUM":
		return Error
	case "HIGH":
		return Error
	default:
		return Note
	}
}

func buildSarifSuppressions(suppressions []gosec.SuppressionInfo) []*Suppression {
	var sarifSuppressionList []*Suppression
	for _, s := range suppressions {
		sarifSuppressionList = append(sarifSuppressionList, NewSuppression(s.Kind, s.Justification))
	}
	return sarifSuppressionList
}
