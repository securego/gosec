package html_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/html"
)

func TestHTML(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "HTML Writer Suite")
}

var _ = Describe("HTML Writer", func() {
	Context("when writing HTML reports", func() {
		It("should write issues in HTML format", func() {
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
			err := html.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<html"))
			Expect(result).To(ContainSubstring("</html>"))
			Expect(result).To(ContainSubstring("/home/src/project/test.go"))
			Expect(result).To(ContainSubstring("Hardcoded credentials"))
			Expect(result).To(ContainSubstring("G101"))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := html.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<html"))
		})

		It("should include statistics in output", func() {
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
			err := html.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("10"))
			Expect(result).To(ContainSubstring("500"))
		})

		It("should escape HTML special characters in rendered output", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Test with special chars",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "x := \"test\"",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := html.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("<html"))
			Expect(result).To(ContainSubstring("</html>"))
			Expect(result).To(ContainSubstring("/test.go"))
		})

		It("should generate valid HTML structure", func() {
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
			err := html.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			htmlCount := strings.Count(result, "<html")
			Expect(htmlCount).To(Equal(1))

			htmlCloseCount := strings.Count(result, "</html>")
			Expect(htmlCloseCount).To(Equal(1))
		})
	})
})
