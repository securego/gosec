package junit

import (
	"html"
	"strconv"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/report/core"
)

func generatePlaintext(issue *gosec.Issue) string {
	return "Results:\n" +
		"[" + issue.File + ":" + issue.Line + "] - " +
		issue.What + " (Confidence: " + strconv.Itoa(int(issue.Confidence)) +
		", Severity: " + strconv.Itoa(int(issue.Severity)) +
		", CWE: " + issue.Cwe.ID + ")\n" + "> " + html.EscapeString(issue.Code)
}

//GenerateReport Convert a gosec report to a JUnit Report
func GenerateReport(data *core.ReportInfo) Report {
	var xmlReport Report
	testsuites := map[string]int{}

	for _, issue := range data.Issues {
		index, ok := testsuites[issue.What]
		if !ok {
			xmlReport.Testsuites = append(xmlReport.Testsuites, &Testsuite{
				Name: issue.What,
			})
			index = len(xmlReport.Testsuites) - 1
			testsuites[issue.What] = index
		}
		testcase := &Testcase{
			Name: issue.File,
			Failure: &Failure{
				Message: "Found 1 vulnerability. See stacktrace for details.",
				Text:    generatePlaintext(issue),
			},
		}

		xmlReport.Testsuites[index].Testcases = append(xmlReport.Testsuites[index].Testcases, testcase)
		xmlReport.Testsuites[index].Tests++
	}

	return xmlReport
}
