package sarif_test

import (
	"bytes"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/report/sarif"
)

var _ = Describe("Sarif Formatter", func() {
	BeforeEach(func() {
	})
	Context("when converting to Sarif issues", func() {
		It("sarif formatted report should contain the result", func() {
			buf := new(bytes.Buffer)
			reportInfo := gosec.NewReportInfo([]*gosec.Issue{}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			err := sarif.WriteReport(buf, reportInfo, []string{})
			result := buf.String()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(ContainSubstring("\"results\": ["))
		})

		It("sarif formatted report should contain the suppressed results", func() {
			ruleID := "G101"
			cwe := gosec.GetCweByRule(ruleID)
			suppressedIssue := gosec.Issue{
				File:       "/home/src/project/test.go",
				Line:       "1",
				Col:        "1",
				RuleID:     ruleID,
				What:       "test",
				Confidence: gosec.High,
				Severity:   gosec.High,
				Code:       "1: testcode",
				Cwe:        cwe,
				Suppressions: []gosec.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}

			reportInfo := gosec.NewReportInfo([]*gosec.Issue{&suppressedIssue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			buf := new(bytes.Buffer)
			err := sarif.WriteReport(buf, reportInfo, []string{})
			result := buf.String()
			Expect(err).ShouldNot(HaveOccurred())

			hasResults, _ := regexp.MatchString(`"results": \[(\s*){`, result)
			Expect(hasResults).To(BeTrue())

			hasSuppressions, _ := regexp.MatchString(`"suppressions": \[(\s*){`, result)
			Expect(hasSuppressions).To(BeTrue())
		})
		It("sarif formatted report should contain the formatted one line code snippet", func() {
			ruleID := "G101"
			cwe := gosec.GetCweByRule(ruleID)
			code := "68: \t\t}\n69: \t\tvar data = template.HTML(v.TmplFile)\n70: \t\tisTmpl := true\n"
			expectedCode := "var data = template.HTML(v.TmplFile)"
			issue := gosec.Issue{
				File:       "/home/src/project/test.go",
				Line:       "69",
				Col:        "14",
				RuleID:     ruleID,
				What:       "test",
				Confidence: gosec.High,
				Severity:   gosec.High,
				Code:       code,
				Cwe:        cwe,
				Suppressions: []gosec.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}
			reportInfo := gosec.NewReportInfo([]*gosec.Issue{&issue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			sarifReport, err := sarif.GenerateReport([]string{}, reportInfo)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sarifReport.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text).Should(Equal(expectedCode))
		})
		It("sarif formatted report should contain the formatted multiple line code snippet", func() {
			ruleID := "G101"
			cwe := gosec.GetCweByRule(ruleID)
			code := "68: }\n69: var data = template.HTML(v.TmplFile)\n70: isTmpl := true\n"
			expectedCode := "var data = template.HTML(v.TmplFile)\nisTmpl := true\n"
			issue := gosec.Issue{
				File:       "/home/src/project/test.go",
				Line:       "69-70",
				Col:        "14",
				RuleID:     ruleID,
				What:       "test",
				Confidence: gosec.High,
				Severity:   gosec.High,
				Code:       code,
				Cwe:        cwe,
				Suppressions: []gosec.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}
			reportInfo := gosec.NewReportInfo([]*gosec.Issue{&issue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			sarifReport, err := sarif.GenerateReport([]string{}, reportInfo)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sarifReport.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text).Should(Equal(expectedCode))
		})
	})
})
