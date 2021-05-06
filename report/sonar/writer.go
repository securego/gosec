package sonar

import (
	"encoding/json"
	"github.com/securego/gosec/v2/report/core"
	"io"
)

//WriteReport write a report in sonar format to the output writer
func WriteReport(w io.Writer, data *core.ReportInfo, rootPaths []string) error {
	si, err := GenerateReport(rootPaths, data)
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
