package text

const templateContent = `Results:
{{range $filePath,$fileErrors := .Errors}}
Golang errors in file: [{{ $filePath }}]:
{{range $index, $error := $fileErrors}}
  > [line {{$error.Line}} : column {{$error.Column}}] - {{$error.Err}}
{{end}}
{{end}}
{{ range $index, $issue := .Issues }}
[{{ highlight $issue.FileLocation $issue.Severity $issue.NoSec }}] - {{ $issue.RuleID }}{{ if $issue.NoSec }} ({{- success "NoSec" -}}){{ end }} ({{ $issue.Cwe.SprintID }}): {{ $issue.What }} (Confidence: {{ $issue.Confidence}}, Severity: {{ $issue.Severity }})
{{ printCode $issue }}

{{ end }}
{{ notice "Summary:" }}
  Gosec  : {{.GosecVersion}}
  Files  : {{.Stats.NumFiles}}
  Lines  : {{.Stats.NumLines}}
  Nosec  : {{.Stats.NumNosec}}
  Issues : {{ if eq .Stats.NumFound 0 }}
	{{- success .Stats.NumFound }}
	{{- else }}
	{{- danger .Stats.NumFound }}
	{{- end }}

`
