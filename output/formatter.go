// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package output

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmlTemplate "html/template"
	"io"
	"strconv"
	"strings"
	plainTemplate "text/template"

	color "github.com/gookit/color"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/formatter"
	"github.com/securego/gosec/v2/sarif"
	"gopkg.in/yaml.v2"
)

// ReportFormat enumerates the output format for reported issues
type ReportFormat int

const (
	// ReportText is the default format that writes to stdout
	ReportText ReportFormat = iota // Plain text format

	// ReportJSON set the output format to json
	ReportJSON // Json format

	// ReportCSV set the output format to csv
	ReportCSV // CSV format

	// ReportJUnitXML set the output format to junit xml
	ReportJUnitXML // JUnit XML format

	// ReportSARIF set the output format to SARIF
	ReportSARIF // SARIF format
)

var text = `Results:
{{range $filePath,$fileErrors := .Errors}}
Golang errors in file: [{{ $filePath }}]:
{{range $index, $error := $fileErrors}}
  > [line {{$error.Line}} : column {{$error.Column}}] - {{$error.Err}}
{{end}}
{{end}}
{{ range $index, $issue := .Issues }}
[{{ highlight $issue.FileLocation $issue.Severity }}] - {{ $issue.RuleID }} (CWE-{{ $issue.Cwe.ID }}): {{ $issue.What }} (Confidence: {{ $issue.Confidence}}, Severity: {{ $issue.Severity }})
{{ printCode $issue }}

{{ end }}
{{ notice "Summary:" }}
   Files: {{.Stats.NumFiles}}
   Lines: {{.Stats.NumLines}}
   Nosec: {{.Stats.NumNosec}}
  Issues: {{ if eq .Stats.NumFound 0 }}
	{{- success .Stats.NumFound }}
	{{- else }}
	{{- danger .Stats.NumFound }}
	{{- end }}

`

// CreateReport generates a report based for the supplied issues and metrics given
// the specified format. The formats currently accepted are: json, yaml, csv, junit-xml, html, sonarqube, golint and text.
func CreateReport(w io.Writer, format string, enableColor bool, rootPaths []string, issues []*gosec.Issue, metrics *gosec.Metrics, errors map[string][]gosec.Error) error {
	data := &formatter.ReportInfo{
		Errors: errors,
		Issues: issues,
		Stats:  metrics,
	}
	var err error
	switch format {
	case "json":
		err = reportJSON(w, data)
	case "yaml":
		err = reportYAML(w, data)
	case "csv":
		err = reportCSV(w, data)
	case "junit-xml":
		err = reportJUnitXML(w, data)
	case "html":
		err = reportFromHTMLTemplate(w, html, data)
	case "text":
		err = reportFromPlaintextTemplate(w, text, enableColor, data)
	case "sonarqube":
		err = reportSonarqube(rootPaths, w, data)
	case "golint":
		err = reportGolint(w, data)
	case "sarif":
		err = reportSARIFTemplate(rootPaths, w, data)
	default:
		err = reportFromPlaintextTemplate(w, text, enableColor, data)
	}
	return err
}

func reportSonarqube(rootPaths []string, w io.Writer, data *formatter.ReportInfo) error {
	si, err := convertToSonarIssues(rootPaths, data)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(si, "", "\t")
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func reportJSON(w io.Writer, data *formatter.ReportInfo) error {
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	_, err = w.Write(raw)
	return err
}

func reportYAML(w io.Writer, data *formatter.ReportInfo) error {
	raw, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func reportCSV(w io.Writer, data *formatter.ReportInfo) error {
	out := csv.NewWriter(w)
	defer out.Flush()
	for _, issue := range data.Issues {
		err := out.Write([]string{
			issue.File,
			issue.Line,
			issue.What,
			issue.Severity.String(),
			issue.Confidence.String(),
			issue.Code,
			fmt.Sprintf("CWE-%s", issue.Cwe.ID),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func reportGolint(w io.Writer, data *formatter.ReportInfo) error {
	// Output Sample:
	// /tmp/main.go:11:14: [CWE-310] RSA keys should be at least 2048 bits (Rule:G403, Severity:MEDIUM, Confidence:HIGH)

	for _, issue := range data.Issues {
		what := issue.What
		if issue.Cwe.ID != "" {
			what = fmt.Sprintf("[CWE-%s] %s", issue.Cwe.ID, issue.What)
		}

		// issue.Line uses "start-end" format for multiple line detection.
		lines := strings.Split(issue.Line, "-")
		start := lines[0]

		_, err := fmt.Fprintf(w, "%s:%s:%s: %s (Rule:%s, Severity:%s, Confidence:%s)\n",
			issue.File,
			start,
			issue.Col,
			what,
			issue.RuleID,
			issue.Severity.String(),
			issue.Confidence.String(),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func reportJUnitXML(w io.Writer, data *formatter.ReportInfo) error {
	junitXMLStruct := createJUnitXMLStruct(data)
	raw, err := xml.MarshalIndent(junitXMLStruct, "", "\t")
	if err != nil {
		return err
	}

	xmlHeader := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	raw = append(xmlHeader, raw...)
	_, err = w.Write(raw)
	if err != nil {
		return err
	}

	return nil
}

func reportSARIFTemplate(rootPaths []string, w io.Writer, data *formatter.ReportInfo) error {
	sr, err := sarif.ConvertToSarifReport(rootPaths, data)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(sr, "", "\t")
	if err != nil {
		return err
	}

	_, err = w.Write(raw)
	return err
}

func reportFromPlaintextTemplate(w io.Writer, reportTemplate string, enableColor bool, data *formatter.ReportInfo) error {
	t, e := plainTemplate.
		New("gosec").
		Funcs(plainTextFuncMap(enableColor)).
		Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func reportFromHTMLTemplate(w io.Writer, reportTemplate string, data *formatter.ReportInfo) error {
	t, e := htmlTemplate.New("gosec").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func plainTextFuncMap(enableColor bool) plainTemplate.FuncMap {
	if enableColor {
		return plainTemplate.FuncMap{
			"highlight": highlight,
			"danger":    color.Danger.Render,
			"notice":    color.Notice.Render,
			"success":   color.Success.Render,
			"printCode": printCodeSnippet,
		}
	}

	// by default those functions return the given content untouched
	return plainTemplate.FuncMap{
		"highlight": func(t string, s gosec.Score) string {
			return t
		},
		"danger":    fmt.Sprint,
		"notice":    fmt.Sprint,
		"success":   fmt.Sprint,
		"printCode": printCodeSnippet,
	}
}

var (
	errorTheme   = color.New(color.FgLightWhite, color.BgRed)
	warningTheme = color.New(color.FgBlack, color.BgYellow)
	defaultTheme = color.New(color.FgWhite, color.BgBlack)
)

// highlight returns content t colored based on Score
func highlight(t string, s gosec.Score) string {
	switch s {
	case gosec.High:
		return errorTheme.Sprint(t)
	case gosec.Medium:
		return warningTheme.Sprint(t)
	default:
		return defaultTheme.Sprint(t)
	}
}

// printCodeSnippet prints the code snippet from the issue by adding a marker to the affected line
func printCodeSnippet(issue *gosec.Issue) string {
	start, end := parseLine(issue.Line)
	scanner := bufio.NewScanner(strings.NewReader(issue.Code))
	var buf bytes.Buffer
	line := start
	for scanner.Scan() {
		codeLine := scanner.Text()
		if strings.HasPrefix(codeLine, strconv.Itoa(line)) && line <= end {
			codeLine = "  > " + codeLine + "\n"
			line++
		} else {
			codeLine = "    " + codeLine + "\n"
		}
		buf.WriteString(codeLine)
	}
	return buf.String()
}

// parseLine extract the start and the end line numbers from a issue line
func parseLine(line string) (int, int) {
	parts := strings.Split(line, "-")
	start := parts[0]
	end := start
	if len(parts) > 1 {
		end = parts[1]
	}
	s, err := strconv.Atoi(start)
	if err != nil {
		return -1, -1
	}
	e, err := strconv.Atoi(end)
	if err != nil {
		return -1, -1
	}
	return s, e
}
