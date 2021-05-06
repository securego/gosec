package csv

import (
	"encoding/csv"
	"fmt"
	"github.com/securego/gosec/v2/report/core"
	"io"
)

//WriteReport write a report in csv format to the output writer
func WriteReport(w io.Writer, data *core.ReportInfo) error {
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
