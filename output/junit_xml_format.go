package output

import (
	"encoding/xml"
	"strconv"

	"github.com/GoASTScanner/gas"
)

type JUnitXMLReport struct {
	XMLName    xml.Name    `xml:"testsuites"`
	Testsuites []Testsuite `xml:"testsuite"`
}

type Testsuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Testcases []Testcase `xml:"testcase"`
}

type Testcase struct {
	XMLName xml.Name `xml:"testcase"`
	Name    string   `xml:"name,attr"`
	Failure Failure  `xml:"failure"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Text    string   `xml:",innerxml"`
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

func createJUnitXMLStruct(groupedData map[string][]*gas.Issue) JUnitXMLReport {
	var xmlReport JUnitXMLReport
	for what, issues := range groupedData {
		testsuite := Testsuite{
			Name:  what,
			Tests: len(issues),
		}
		for _, issue := range issues {
			text := "Results:\n"
			text += "[" + issue.File + ":" + issue.Line + "] - " +
				issue.What + " (Confidence: " + strconv.Itoa(int(issue.Confidence)) +
				", Severity: " + strconv.Itoa(int(issue.Severity)) + ")\n"
			text += "> " + issue.Code

			testcase := Testcase{
				Name: issue.File,
				Failure: Failure{
					Message: "Found 1 vulnerability. See stacktrace for details.",
					Text:    text,
				},
			}
			testsuite.Testcases = append(testsuite.Testcases, testcase)
		}
		xmlReport.Testsuites = append(xmlReport.Testsuites, testsuite)
	}
	return xmlReport
}
