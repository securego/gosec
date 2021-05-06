package sarif

import (
	"encoding/json"
	"github.com/securego/gosec/v2/report/core"
	"io"
)

//WriteReport write a report in SARIF format to the output writer
func WriteReport(w io.Writer, data *core.ReportInfo,rootPaths []string) error {
	sr, err := GenerateReport(rootPaths, data)
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
