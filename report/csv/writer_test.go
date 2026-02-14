package csv_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/csv"
)

func TestCSV(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CSV Writer Suite")
}

var _ = Describe("CSV Writer", func() {
	Context("when writing CSV reports", func() {
		It("should write issues in CSV format", func() {
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
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := csv.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("/home/src/project/test.go"))
			Expect(result).To(ContainSubstring("1"))
			Expect(result).To(ContainSubstring("Hardcoded credentials"))
			Expect(result).To(ContainSubstring("MEDIUM"))
			Expect(result).To(ContainSubstring("HIGH"))
			Expect(result).To(ContainSubstring("CWE-798"))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := csv.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(0))
		})

		It("should handle multiple issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test1.go",
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
						File:       "/test2.go",
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
			err := csv.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			lines := strings.Split(strings.TrimSpace(result), "\n")
			Expect(lines).To(HaveLen(2))
			Expect(result).To(ContainSubstring("/test1.go"))
			Expect(result).To(ContainSubstring("/test2.go"))
		})
	})
})
