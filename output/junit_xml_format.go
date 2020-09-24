package output

import (
	"encoding/xml"
	htmlLib "html"
	"strconv"

	"github.com/securego/gosec/v2"
)

type junitXMLReport struct {
	XMLName    xml.Name    `xml:"testsuites"`
	Testsuites []testsuite `xml:"testsuite"`
}

type testsuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Testcases []testcase `xml:"testcase"`
}

type testcase struct {
	XMLName xml.Name `xml:"testcase"`
	Name    string   `xml:"name,attr"`
	Failure failure  `xml:"failure"`
}

type failure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Text    string   `xml:",innerxml"`
}

func generatePlaintext(issue *gosec.Issue) string {
	return "Results:\n" +
		"[" + issue.File + ":" + issue.Line + "] - " +
		issue.What + " (Confidence: " + strconv.Itoa(int(issue.Confidence)) +
		", Severity: " + strconv.Itoa(int(issue.Severity)) +
		", CWE: " + issue.Cwe.ID + ")\n" + "> " + htmlLib.EscapeString(issue.Code)
}

func createJUnitXMLStruct(data *reportInfo) junitXMLReport {
	var xmlReport junitXMLReport
	testsuites := map[string]int{}

	for _, issue := range data.Issues {
		index, ok := testsuites[issue.What]
		if !ok {
			xmlReport.Testsuites = append(xmlReport.Testsuites, testsuite{
				Name: issue.What,
			})
			index = len(xmlReport.Testsuites) - 1
			testsuites[issue.What] = index
		}
		testcase := testcase{
			Name: issue.File,
			Failure: failure{
				Message: "Found 1 vulnerability. See stacktrace for details.",
				Text:    generatePlaintext(issue),
			},
		}

		xmlReport.Testsuites[index].Testcases = append(xmlReport.Testsuites[index].Testcases, testcase)
		xmlReport.Testsuites[index].Tests++
	}

	return xmlReport
}
