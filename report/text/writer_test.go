package text_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/text"
)

func TestText(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Text Writer Suite")
}

var _ = Describe("Text Writer", func() {
	Context("when writing text reports", func() {
		It("should write issues in text format", func() {
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
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("/home/src/project/test.go"))
			Expect(result).To(ContainSubstring("Hardcoded credentials"))
			Expect(result).To(ContainSubstring("G101"))
			Expect(result).To(ContainSubstring("password := \"secret\""))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Summary:"))
		})

		It("should include summary statistics", func() {
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
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Summary:"))
			Expect(result).To(ContainSubstring("10"))
			Expect(result).To(ContainSubstring("500"))
			Expect(result).To(ContainSubstring("2"))
			Expect(result).To(ContainSubstring("5"))
		})

		It("should support color output when enabled", func() {
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
			err := text.WriteReport(buf, data, true)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).ToNot(BeEmpty())
		})

		It("should format code snippets correctly", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "10-12",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "line1\nline2\nline3",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			lines := strings.Split(result, "\n")
			Expect(len(lines)).To(BeNumerically(">", 5))
		})

		It("should display severity and confidence levels", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Issue",
						Confidence: issue.Low,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Severity"))
			Expect(result).To(ContainSubstring("Confidence"))
		})

		It("should handle errors in the report", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{
					"/test.go": {
						{Line: 1, Column: 1, Err: "syntax error"},
					},
				},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := text.WriteReport(buf, data, false)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Golang errors"))
			Expect(result).To(ContainSubstring("syntax error"))
		})
	})
})
