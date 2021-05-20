package html

import (
	"html/template"
	"io"

	"github.com/securego/gosec/v2"
)

//WriteReport write a report in html format to the output writer
func WriteReport(w io.Writer, data *gosec.ReportInfo) error {
	t, e := template.New("gosec").Parse(templateContent)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}
