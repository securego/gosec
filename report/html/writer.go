package html

import (
	"github.com/securego/gosec/v2/report/core"
	"html/template"
	"io"
)

//WriteReport write a report in html format to the output writer
func WriteReport(w io.Writer, data *core.ReportInfo) error {
	t, e := template.New("gosec").Parse(templateContent)
	if e != nil {
		return e
	}

	return t.Execute(w, data)
}
