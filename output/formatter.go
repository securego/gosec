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
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	htmlTemplate "html/template"
	"io"
	plainTemplate "text/template"

	"github.com/GoASTScanner/gas"
)

// ReportFormat enumrates the output format for reported issues
type ReportFormat int

const (
	// ReportText is the default format that writes to stdout
	ReportText ReportFormat = iota // Plain text format

	// ReportJSON set the output format to json
	ReportJSON // Json format

	// ReportCSV set the output format to csv
	ReportCSV // CSV format

	// ReportXML set the output format to junit xml
	ReportXML // JUnit XML format
)

var text = `Results:
{{ range $index, $issue := .Issues }}
[{{ $issue.File }}:{{ $issue.Line }}] - {{ $issue.What }} (Confidence: {{ $issue.Confidence}}, Severity: {{ $issue.Severity }})
  > {{ $issue.Code }}

{{ end }}
Summary:
   Files: {{.Stats.NumFiles}}
   Lines: {{.Stats.NumLines}}
   Nosec: {{.Stats.NumNosec}}
  Issues: {{.Stats.NumFound}}

`

type reportInfo struct {
	Issues []*gas.Issue
	Stats  *gas.Metrics
}

type XMLReport struct {
	XMLName    xml.Name    `xml:"testsuites"`
	Testsuites []Testsuite `xml:"testsuite"`
}

type Testsuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Testcases []Testcase `xml:"testcase"`
}

type Testcase struct {
	XMLName xml.Name `xml:"testcase"`
	Name    string   `xml:"name,attr"`
	Failure Failure  `xml:"failure"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Text    string   `xml:",innerxml"`
}

// CreateReport generates a report based for the supplied issues and metrics given
// the specified format. The formats currently accepted are: json, csv, html and text.
func CreateReport(w io.Writer, format string, issues []*gas.Issue, metrics *gas.Metrics) error {
	data := &reportInfo{
		Issues: issues,
		Stats:  metrics,
	}
	var err error
	switch format {
	case "json":
		err = reportJSON(w, data)
	case "csv":
		err = reportCSV(w, data)
	case "xml":
		err = reportXML(w, data)
	case "html":
		err = reportFromHTMLTemplate(w, html, data)
	case "text":
		err = reportFromPlaintextTemplate(w, text, data)
	default:
		err = reportFromPlaintextTemplate(w, text, data)
	}
	return err
}

func reportJSON(w io.Writer, data *reportInfo) error {
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		panic(err)
	}

	_, err = w.Write(raw)
	if err != nil {
		panic(err)
	}
	return err
}

func reportCSV(w io.Writer, data *reportInfo) error {
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
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func reportXML(w io.Writer, data *reportInfo) error {
	testsuites := make(map[string][]Testcase)
	for _, issue := range data.Issues {
		stacktrace, err := json.MarshalIndent(issue, "", "\t")
		if err != nil {
			panic(err)
		}
		testcase := Testcase{
			Name: issue.File,
			Failure: Failure{
				Message: "Found 1 vulnerability. See stacktrace for details.",
				Text:    string(stacktrace),
			},
		}
		if _, ok := testsuites[issue.What]; ok {
			testsuites[issue.What] = append(testsuites[issue.What], testcase)
		} else {
			testsuites[issue.What] = []Testcase{testcase}
		}
	}

	var xmlReport XMLReport
	for what, testcases := range testsuites {
		testsuite := Testsuite{
			Name:  what,
			Tests: len(testcases),
		}
		for _, testcase := range testcases {
			testsuite.Testcases = append(testsuite.Testcases, testcase)
		}
		xmlReport.Testsuites = append(xmlReport.Testsuites, testsuite)
	}

	raw, err := xml.Marshal(xmlReport)
	if err != nil {
		panic(err)
	}

	_, err = w.Write(raw)
	if err != nil {
		panic(err)
	}

	return err
}

func reportFromPlaintextTemplate(w io.Writer, reportTemplate string, data *reportInfo) error {
	t, e := plainTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func reportFromHTMLTemplate(w io.Writer, reportTemplate string, data *reportInfo) error {
	t, e := htmlTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}
