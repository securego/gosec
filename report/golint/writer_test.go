package golint_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/golint"
)

func TestGolint(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Golint Writer Suite")
}

var _ = Describe("Golint Writer", func() {
	Context("when writing golint format reports", func() {
		It("should write issues in golint format", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/home/src/project/test.go",
						Line:       "11",
						Col:        "14",
						RuleID:     "G403",
						What:       "RSA keys should be at least 2048 bits",
						Confidence: issue.High,
						Severity:   issue.Medium,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G403"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			// Expected format: /tmp/main.go:11:14: [CWE-310] RSA keys should be at least 2048 bits (Rule:G403, Severity:MEDIUM, Confidence:HIGH)
			Expect(result).To(ContainSubstring("/home/src/project/test.go:11:14:"))
			Expect(result).To(ContainSubstring("[CWE-310]"))
			Expect(result).To(ContainSubstring("RSA keys should be at least 2048 bits"))
			Expect(result).To(ContainSubstring("(Rule:G403"))
			Expect(result).To(ContainSubstring("Severity:MEDIUM"))
			Expect(result).To(ContainSubstring("Confidence:HIGH)"))
		})

		It("should handle empty issues", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{},
				Stats:  &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(buf.Len()).To(Equal(0))
		})

		It("should handle line ranges correctly", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "10-15",
						Col:        "1",
						RuleID:     "G101",
						What:       "Multi-line issue",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			// Should use start line from range
			Expect(result).To(ContainSubstring("/test.go:10:1:"))
		})

		It("should handle issues without CWE", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "CUSTOM",
						What:       "Custom issue",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        nil,
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			// Should not include [CWE-...] prefix
			Expect(result).ToNot(ContainSubstring("[CWE-"))
			Expect(result).To(ContainSubstring("Custom issue"))
		})

		It("should format multiple issues", func() {
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
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			lines := strings.Split(strings.TrimSpace(result), "\n")
			Expect(lines).To(HaveLen(2))
			Expect(result).To(ContainSubstring("/test1.go:10:1:"))
			Expect(result).To(ContainSubstring("/test2.go:20:2:"))
		})

		It("should format file:line:col correctly", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/path/to/file.go",
						Line:       "42",
						Col:        "8",
						RuleID:     "G101",
						What:       "Test",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(MatchRegexp(`/path/to/file\.go:42:8:`))
		})

		It("should include all severity levels", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "High",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G101"),
					},
					{
						File:       "/test.go",
						Line:       "2",
						Col:        "1",
						RuleID:     "G102",
						What:       "Medium",
						Confidence: issue.Medium,
						Severity:   issue.Medium,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G102"),
					},
					{
						File:       "/test.go",
						Line:       "3",
						Col:        "1",
						RuleID:     "G103",
						What:       "Low",
						Confidence: issue.Low,
						Severity:   issue.Low,
						Code:       "code",
						Cwe:        issue.GetCweByRule("G103"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := golint.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("Severity:HIGH"))
			Expect(result).To(ContainSubstring("Severity:MEDIUM"))
			Expect(result).To(ContainSubstring("Severity:LOW"))
		})
	})
})
