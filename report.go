package gosec

// ReportInfo this is report information
type ReportInfo struct {
	Errors map[string][]Error `json:"Golang errors"`
	Issues []*Issue
	Stats  *Metrics
}

// NewReportInfo instantiate a ReportInfo
func NewReportInfo(issues []*Issue, metrics *Metrics, errors map[string][]Error) *ReportInfo {
	return &ReportInfo{
		Errors: errors,
		Issues: issues,
		Stats:  metrics,
	}
}
