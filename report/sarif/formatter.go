package sarif

import (
	"fmt"
	"github.com/google/uuid"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/cwe"
	"github.com/securego/gosec/v2/report/core"
)

type sarifLevel string

const (
	sarifNone    = sarifLevel("none")
	sarifNote    = sarifLevel("note")
	sarifWarning = sarifLevel("warning")
	sarifError   = sarifLevel("error")
)

//GenerateReport Convert a gosec report to a Sarif Report
func GenerateReport(rootPaths []string, data *core.ReportInfo) (*Report, error) {

	type rule struct {
		index int
		rule  *ReportingDescriptor
	}

	rules := make([]*ReportingDescriptor, 0)
	rulesIndices := make(map[string]rule)
	lastRuleIndex := -1

	results := []*Result{}
	taxa := make([]*ReportingDescriptor, 0)
	weaknesses := make(map[string]*cwe.Weakness)

	for _, issue := range data.Issues {
		_, ok := weaknesses[issue.Cwe.ID]
		if !ok {
			weakness := cwe.Get(issue.Cwe.ID)
			weaknesses[issue.Cwe.ID] = weakness
			taxon := parseSarifTaxon(weakness)
			taxa = append(taxa, taxon)
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

		result := buildSarifResult(r.rule.ID, r.index, issue, []*Location{location})

		results = append(results, result)
	}

	tool := buildSarifTool(buildSarifDriver(rules))

	run := buildSarifRun(results, buildSarifTaxonomies(taxa), tool)

	return buildSarifReport(run), nil
}

func buildSarifResult(ruleID string, index int, issue *gosec.Issue, locations []*Location) *Result {
	return &Result{
		RuleID:    ruleID,
		RuleIndex: index,
		Level:     getSarifLevel(issue.Severity.String()),
		Message: &Message{
			Text: issue.What,
		},
		Locations: locations,
	}
}

// buildSarifReport return SARIF report struct
func buildSarifReport(run *Run) *Report {
	return &Report{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []*Run{run},
	}
}

// parseSarifRule return SARIF rule field struct
func parseSarifRule(issue *gosec.Issue) *ReportingDescriptor {
	return &ReportingDescriptor{
		ID:   issue.RuleID,
		Name: issue.What,
		ShortDescription: &MultiformatMessageString{
			Text: issue.What,
		},
		FullDescription: &MultiformatMessageString{
			Text: issue.What,
		},
		Help: &MultiformatMessageString{
			Text: fmt.Sprintf("%s\nSeverity: %s\nConfidence: %s\n", issue.What, issue.Severity.String(), issue.Confidence.String()),
		},
		Properties: &PropertyBag{
			Tags: []string{"security", issue.Severity.String()},
			AdditionalProperties: map[string]interface{}{
				"precision": strings.ToLower(issue.Confidence.String()),
			},
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
			ID:   weakness.ID,
			GUID: uuid3(weakness.SprintID()),
			ToolComponent: &ToolComponentReference{
				Name: cwe.Acronym,
			},
		},
		Kinds: []string{"superset"},
	}
}

func buildSarifTool(driver *ToolComponent) *Tool {
	return &Tool{
		Driver: driver,
	}
}

func buildSarifTaxonomies(taxa []*ReportingDescriptor) []*ToolComponent {
	return []*ToolComponent{
		buildCWETaxonomy("4.4", taxa),
	}
}

func buildCWETaxonomy(version string, taxa []*ReportingDescriptor) *ToolComponent {
	return &ToolComponent{
		Name:           cwe.Acronym,
		Version:        version,
		ReleaseDateUtc: "2021-03-15",
		InformationURI: fmt.Sprintf("https://cwe.mitre.org/data/published/cwe_v%s.pdf/", version),
		DownloadURI:    fmt.Sprintf("https://cwe.mitre.org/data/xml/cwec_v%s.xml.zip", version),
		Organization:   "MITRE",
		ShortDescription: &MultiformatMessageString{
			Text: "The MITRE Common Weakness Enumeration",
		},
		GUID:            uuid3(cwe.Acronym),
		IsComprehensive: true,
		MinimumRequiredLocalizedDataSemanticVersion: version,
		Taxa: taxa,
	}
}

func parseSarifTaxon(weakness *cwe.Weakness) *ReportingDescriptor {
	return &ReportingDescriptor{
		ID:      weakness.ID,
		Name:    weakness.Name,
		GUID:    uuid3(weakness.SprintID()),
		HelpURI: weakness.SprintURL(),
		ShortDescription: &MultiformatMessageString{
			Text: weakness.Description,
		},
	}
}

func buildSarifDriver(rules []*ReportingDescriptor) *ToolComponent {
	buildInfo, ok := debug.ReadBuildInfo()
	var gosecVersion string
	if ok {
		gosecVersion = buildInfo.Main.Version[1:]
	} else {
		gosecVersion = "devel"
	}
	return &ToolComponent{
		Name:    "gosec",
		Version: gosecVersion,
		SupportedTaxonomies: []*ToolComponentReference{
			{Name: cwe.Acronym, GUID: uuid3(cwe.Acronym)},
		},
		InformationURI: "https://github.com/securego/gosec/",
		Rules:          rules,
	}
}

func uuid3(value string) string {
	return uuid.NewMD5(uuid.Nil, []byte(value)).String()
}

func buildSarifRun(results []*Result, taxonomies []*ToolComponent, tool *Tool) *Run {
	return &Run{
		Results:    results,
		Taxonomies: taxonomies,
		Tool:       tool,
	}
}

// parseSarifLocation return SARIF location struct
func parseSarifLocation(issue *gosec.Issue, rootPaths []string) (*Location, error) {
	region, err := parseSarifRegion(issue)
	if err != nil {
		return nil, err
	}
	artifactLocation := parseSarifArtifactLocation(issue, rootPaths)
	return buildSarifLocation(buildSarifPhysicalLocation(artifactLocation, region)), nil
}

func buildSarifLocation(physicalLocation *PhysicalLocation) *Location {
	return &Location{
		PhysicalLocation: physicalLocation,
	}
}

func buildSarifPhysicalLocation(artifactLocation *ArtifactLocation, region *Region) *PhysicalLocation {
	return &PhysicalLocation{
		ArtifactLocation: artifactLocation,
		Region:           region,
	}
}

func parseSarifArtifactLocation(issue *gosec.Issue, rootPaths []string) *ArtifactLocation {
	var filePath string
	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			filePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}
	return buildSarifArtifactLocation(filePath)
}

func buildSarifArtifactLocation(uri string) *ArtifactLocation {
	return &ArtifactLocation{
		URI: uri,
	}
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
	return buildSarifRegion(startLine, endLine, col), nil
}

func buildSarifRegion(startLine int, endLine int, col int) *Region {
	return &Region{
		StartLine:      startLine,
		EndLine:        endLine,
		StartColumn:    col,
		EndColumn:      col,
		SourceLanguage: "go",
	}
}

// From https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127839
// * "warning": The rule specified by ruleId was evaluated and a problem was found.
// * "error": The rule specified by ruleId was evaluated and a serious problem was found.
// * "note": The rule specified by ruleId was evaluated and a minor problem or an opportunity to improve the code was found.
// * "none": The concept of “severity” does not apply to this result because the kind property (§3.27.9) has a value other than "fail".
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
