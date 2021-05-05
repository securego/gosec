package formatter

import (
	"github.com/securego/gosec/v2"
)

//ReportInfo this is report information
type ReportInfo struct {
	Errors map[string][]gosec.Error `json:"Golang errors"`
	Issues []*gosec.Issue
	Stats  *gosec.Metrics
}
