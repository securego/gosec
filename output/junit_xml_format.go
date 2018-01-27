package output

import (
	"encoding/xml"
	"strconv"

	"github.com/GoASTScanner/gas"
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

func generatePlaintext(issue *gas.Issue) string {
	return "Results:\n" +
		"[" + issue.File + ":" + issue.Line + "] - " +
		issue.What + " (Confidence: " + strconv.Itoa(int(issue.Confidence)) +
		", Severity: " + strconv.Itoa(int(issue.Severity)) + ")\n" + "> " + issue.Code
}

func groupDataByRules(data *reportInfo) map[string][]*gas.Issue {
	groupedData := make(map[string][]*gas.Issue)
	for _, issue := range data.Issues {
		if _, ok := groupedData[issue.What]; ok {
			groupedData[issue.What] = append(groupedData[issue.What], issue)
		} else {
			groupedData[issue.What] = []*gas.Issue{issue}
		}
	}
	return groupedData
}

func createJUnitXMLStruct(groupedData map[string][]*gas.Issue) junitXMLReport {
	var xmlReport junitXMLReport
	for what, issues := range groupedData {
		testsuite := testsuite{
			Name:  what,
			Tests: len(issues),
		}
		for _, issue := range issues {
			testcase := testcase{
				Name: issue.File,
				Failure: failure{
					Message: "Found 1 vulnerability. See stacktrace for details.",
					Text:    generatePlaintext(issue),
				},
			}
			testsuite.Testcases = append(testsuite.Testcases, testcase)
		}
		xmlReport.Testsuites = append(xmlReport.Testsuites, testsuite)
	}
	return xmlReport
}
