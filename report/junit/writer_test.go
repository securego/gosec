package junit_test

import (
	"bytes"
	"encoding/xml"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/junit"
)

func TestJUnit(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "JUnit Writer Suite")
}

var _ = Describe("JUnit Writer", func() {
	Context("when writing JUnit XML reports", func() {
		It("should write issues in JUnit XML format", func() {
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
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<?xml"))
			Expect(result).To(ContainSubstring("<testsuites"))
			Expect(result).To(ContainSubstring("</testsuites>"))
			Expect(result).To(ContainSubstring("/home/src/project/test.go"))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<testsuites"))
		})

		It("should produce valid XML", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			type TestSuites struct {
				XMLName xml.Name `xml:"testsuites"`
			}
			var result TestSuites
			err = xml.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should include test and testsuite elements", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "10",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue 1",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code1",
						Cwe:        issue.GetCweByRule("G101"),
					},
					{
						File:       "/test.go",
						Line:       "20",
						Col:        "2",
						RuleID:     "G102",
						What:       "Issue 2",
						Confidence: issue.Medium,
						Severity:   issue.Low,
						Code:       "code2",
						Cwe:        issue.GetCweByRule("G102"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<testsuite"))
			Expect(result).To(ContainSubstring("<testcase"))
			Expect(result).To(ContainSubstring("</testcase>"))
			Expect(result).To(ContainSubstring("</testsuite>"))
		})

		It("should handle special characters in issue details", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/a&b<c>.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Test & <issue>",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "x := \"a & b < c\"",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			type testcase struct {
				Name    string `xml:"name,attr"`
				Failure string `xml:"failure"`
			}
			type testsuite struct {
				Testcases []testcase `xml:"testcase"`
			}
			type testsuites struct {
				XMLName    xml.Name    `xml:"testsuites"`
				Testsuites []testsuite `xml:"testsuite"`
			}
			var result testsuites
			err = xml.Unmarshal(buf.Bytes(), &result)
			Expect(err).ShouldNot(HaveOccurred())

			Expect(result.Testsuites).To(HaveLen(1))
			Expect(result.Testsuites[0].Testcases).To(HaveLen(1))
			tc := result.Testsuites[0].Testcases[0]
			Expect(tc.Name).To(Equal("/a&b<c>.go"))
			// The decoded failure body must contain the original characters
			// exactly once, which proves it is neither raw nor double escaped.
			Expect(tc.Failure).To(ContainSubstring("[/a&b<c>.go:1]"))
			Expect(tc.Failure).To(ContainSubstring("Test & <issue>"))
			Expect(tc.Failure).To(ContainSubstring("> x := \"a & b < c\""))
			Expect(tc.Failure).ShouldNot(ContainSubstring("&amp;"))
			Expect(tc.Failure).ShouldNot(ContainSubstring("&#34;"))
		})

		It("should handle multiple issues from different files", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/file1.go",
						Line:       "10",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue in file1",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code1",
						Cwe:        issue.GetCweByRule("G101"),
					},
					{
						File:       "/file2.go",
						Line:       "20",
						Col:        "2",
						RuleID:     "G102",
						What:       "Issue in file2",
						Confidence: issue.Medium,
						Severity:   issue.Low,
						Code:       "code2",
						Cwe:        issue.GetCweByRule("G102"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("/file1.go"))
			Expect(result).To(ContainSubstring("/file2.go"))
			Expect(result).To(ContainSubstring("Issue in file1"))
			Expect(result).To(ContainSubstring("Issue in file2"))
		})

		It("should include severity information in output", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := junit.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Severity:"))
			Expect(result).To(ContainSubstring("Confidence:"))
		})
	})
})
