package gosec

//ReportInfo this is report information
type ReportInfo struct {
	Errors map[string][]Error `json:"Golang errors"`
	Issues []*Issue
	Stats  *Metrics
}
