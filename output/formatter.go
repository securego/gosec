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
	"io"
	"text/template"

	gas "github.com/HewlettPackard/gas/core"
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

var json = `{
        "metrics": {
            "files": {{.Stats.NumFiles}},
            "lines": {{.Stats.NumLines}},
            "nosec": {{.Stats.NumNosec}},
            "issues": {{.Stats.NumFound}}
        },
        "issues": [
        {{ range $index, $issue := .Issues }}{{ if $index }}, {{ end }}{
          "file": "{{ $issue.File }}",
          "line": "{{ $issue.Line }}",
          "details": "{{ $issue.What }}",
          "confidence": "{{ $issue.Confidence }}",
          "severity": "{{ $issue.Severity }}",
          "code": "{{ js $issue.Code }}"
        }{{ end }}
        ]
}`

var csv = `{{ range $index, $issue := .Issues -}}
{{- $issue.File -}},
{{- $issue.Line -}},
{{- $issue.What -}},
{{- $issue.Severity -}},
{{- $issue.Confidence -}},
{{- printf "%q" $issue.Code }}
{{ end }}`

func CreateReport(w io.Writer, format string, data *gas.Analyzer) error {
	reportType := text

	switch format {
	case "csv":
		reportType = csv
	case "json":
		reportType = json
	case "text":
		reportType = text
	default:
		reportType = text
	}

	t, e := template.New("gas").Parse(reportType)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}
