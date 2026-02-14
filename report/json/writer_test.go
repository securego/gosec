package json_test

import (
	"bytes"
	"encoding/json"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	jsonreport "github.com/securego/gosec/v2/report/json"
)

func TestJSON(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JSON Writer Suite")
}

var _ = Describe("JSON Writer", func() {
	Context("when writing JSON reports", func() {
		It("should write issues in JSON format", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/home/src/project/test.go",
						Line:       "1",
						Col:        "5",
						RuleID:     "G101",
						What:       "Hardcoded credentials",
						Confidence: issue.High,
						Severity:   issue.Medium,
						Code:       "password := \"secret\"",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{
					NumFiles: 1,
					NumLines: 100,
					NumNosec: 0,
					NumFound: 1,
				},
			}

			buf := new(bytes.Buffer)
			err := jsonreport.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(result).To(HaveKey("Issues"))
			issues := result["Issues"].([]interface{})
			Expect(issues).To(HaveLen(1))

			firstIssue := issues[0].(map[string]interface{})
			Expect(firstIssue["file"]).To(Equal("/home/src/project/test.go"))
			Expect(firstIssue["line"]).To(Equal("1"))
			Expect(firstIssue["rule_id"]).To(Equal("G101"))
			Expect(firstIssue["details"]).To(Equal("Hardcoded credentials"))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := jsonreport.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(HaveKey("Issues"))
		})

		It("should include statistics", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats: &gosec.Metrics{
					NumFiles: 10,
					NumLines: 500,
					NumNosec: 2,
					NumFound: 5,
				},
			}

			buf := new(bytes.Buffer)
			err := jsonreport.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(result).To(HaveKey("Stats"))
			stats := result["Stats"].(map[string]interface{})
			Expect(stats["files"]).To(BeNumerically("==", 10))
			Expect(stats["lines"]).To(BeNumerically("==", 500))
			Expect(stats["nosec"]).To(BeNumerically("==", 2))
			Expect(stats["found"]).To(BeNumerically("==", 5))
		})

		It("should escape special characters", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Quote: \" Backslash: \\ Newline: \n",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "x := \"test\"",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := jsonreport.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())

			issues := result["Issues"].([]interface{})
			firstIssue := issues[0].(map[string]interface{})
			details := firstIssue["details"].(string)
			Expect(details).To(ContainSubstring("Quote: \""))
			Expect(details).To(ContainSubstring("Backslash: \\"))
		})
	})
})
