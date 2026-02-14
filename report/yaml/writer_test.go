package yaml_test

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/yaml"
)

func TestYAML(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "YAML Writer Suite")
}

var _ = Describe("YAML Writer", func() {
	Context("when writing YAML reports", func() {
		It("should write issues in YAML format", func() {
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
			err := yaml.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("issues:"))
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
			err := yaml.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("issues: []"))
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
			err := yaml.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			Expect(result).To(ContainSubstring("stats:"))
			Expect(result).To(ContainSubstring("numfiles: 10"))
			Expect(result).To(ContainSubstring("numlines: 500"))
			Expect(result).To(ContainSubstring("numnosec: 2"))
			Expect(result).To(ContainSubstring("numfound: 5"))
		})

		It("should handle multiline strings", func() {
			data := &gosec.ReportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*issue.Issue{
					{
						File:       "/test.go",
						Line:       "1",
						Col:        "1",
						RuleID:     "G101",
						What:       "Line 1\nLine 2\nLine 3",
						Confidence: issue.High,
						Severity:   issue.High,
						Code:       "code := \"test\"\nmore code",
						Cwe:        issue.GetCweByRule("G101"),
					},
				},
				Stats: &gosec.Metrics{},
			}

			buf := new(bytes.Buffer)
			err := yaml.WriteReport(buf, data)
			Expect(err).ShouldNot(HaveOccurred())

			result := buf.String()
			lines := strings.Split(result, "\n")
			Expect(len(lines)).To(BeNumerically(">", 10))
		})
	})
})
