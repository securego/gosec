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
	htmlTemplate "html/template"
	"io"
	"strconv"
	plainTemplate "text/template"

	gas "github.com/GoASTScanner/gas/core"
)

// The output format for reported issues
type ReportFormat int

const (
	ReportText ReportFormat = iota // Plain text format
	ReportJSON                     // Json format
	ReportCSV                      // CSV format
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

func CreateReport(w io.Writer, format string, data *gas.Analyzer) error {
	var err error
	switch format {
	case "json":
		err = reportJSON(w, data)
	case "csv":
		err = reportCSV(w, data)
	case "html":
		err = reportFromHTMLTemplate(w, html, data)
	case "text":
		err = reportFromPlaintextTemplate(w, text, data)
	default:
		err = reportFromPlaintextTemplate(w, text, data)
	}
	return err
}

func reportJSON(w io.Writer, data *gas.Analyzer) error {
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

func reportCSV(w io.Writer, data *gas.Analyzer) error {
	out := csv.NewWriter(w)
	defer out.Flush()
	for _, issue := range data.Issues {
		err := out.Write([]string{
			issue.File,
			strconv.Itoa(issue.Line),
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

func reportFromPlaintextTemplate(w io.Writer, reportTemplate string, data *gas.Analyzer) error {
	t, e := plainTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}

func reportFromHTMLTemplate(w io.Writer, reportTemplate string, data *gas.Analyzer) error {
	t, e := htmlTemplate.New("gas").Parse(reportTemplate)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}
