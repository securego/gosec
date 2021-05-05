package json

import (
	"encoding/json"
	"github.com/securego/gosec/v2/report/core"
	"io"
)

//WriteReport write a report in json format to the output writer
func WriteReport(w io.Writer, data *core.ReportInfo) error {
	raw, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	_, err = w.Write(raw)
	return err
}
