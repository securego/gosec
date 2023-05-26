package sarif_test

import (
	"bytes"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/report/sarif"
)

var _ = Describe("Sarif Formatter", func() {
	BeforeEach(func() {
	})
	Context("when converting to Sarif issues", func() {
		It("sarif formatted report should contain the result", func() {
			buf := new(bytes.Buffer)
			reportInfo := gosec.NewReportInfo([]*issue.Issue{}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			err := sarif.WriteReport(buf, reportInfo, []string{})
			result := buf.String()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(ContainSubstring("\"results\": ["))
		})

		It("sarif formatted report should contain the suppressed results", func() {
			ruleID := "G101"
			cwe := issue.GetCweByRule(ruleID)
			suppressedIssue := issue.Issue{
				File:       "/home/src/project/test.go",
				Line:       "1",
				Col:        "1",
				RuleID:     ruleID,
				What:       "test",
				Confidence: issue.High,
				Severity:   issue.High,
				Code:       "1: testcode",
				Cwe:        cwe,
				Suppressions: []issue.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}

			reportInfo := gosec.NewReportInfo([]*issue.Issue{&suppressedIssue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
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
			cwe := issue.GetCweByRule(ruleID)
			code := "68: \t\t}\n69: \t\tvar data = template.HTML(v.TmplFile)\n70: \t\tisTmpl := true\n"
			expectedCode := "var data = template.HTML(v.TmplFile)"
			newissue := issue.Issue{
				File:       "/home/src/project/test.go",
				Line:       "69",
				Col:        "14",
				RuleID:     ruleID,
				What:       "test",
				Confidence: issue.High,
				Severity:   issue.High,
				Code:       code,
				Cwe:        cwe,
				Suppressions: []issue.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}
			reportInfo := gosec.NewReportInfo([]*issue.Issue{&newissue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			sarifReport, err := sarif.GenerateReport([]string{}, reportInfo)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sarifReport.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text).Should(Equal(expectedCode))
		})
		It("sarif formatted report should contain the formatted multiple line code snippet", func() {
			ruleID := "G101"
			cwe := issue.GetCweByRule(ruleID)
			code := "68: }\n69: var data = template.HTML(v.TmplFile)\n70: isTmpl := true\n"
			expectedCode := "var data = template.HTML(v.TmplFile)\nisTmpl := true\n"
			newissue := issue.Issue{
				File:       "/home/src/project/test.go",
				Line:       "69-70",
				Col:        "14",
				RuleID:     ruleID,
				What:       "test",
				Confidence: issue.High,
				Severity:   issue.High,
				Code:       code,
				Cwe:        cwe,
				Suppressions: []issue.SuppressionInfo{
					{
						Kind:          "kind",
						Justification: "justification",
					},
				},
			}
			reportInfo := gosec.NewReportInfo([]*issue.Issue{&newissue}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			sarifReport, err := sarif.GenerateReport([]string{}, reportInfo)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(sarifReport.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text).Should(Equal(expectedCode))
		})
		It("sarif formatted report should have proper rule index", func() {
			rules := []string{"G404", "G101", "G102", "G103"}
			issues := []*issue.Issue{}
			for _, rule := range rules {
				cwe := issue.GetCweByRule(rule)
				newissue := issue.Issue{
					File:       "/home/src/project/test.go",
					Line:       "69-70",
					Col:        "14",
					RuleID:     rule,
					What:       "test",
					Confidence: issue.High,
					Severity:   issue.High,
					Cwe:        cwe,
					Suppressions: []issue.SuppressionInfo{
						{
							Kind:          "kind",
							Justification: "justification",
						},
					},
				}
				issues = append(issues, &newissue)

			}
			dupRules := []string{"G102", "G404"}
			for _, rule := range dupRules {
				cwe := issue.GetCweByRule(rule)
				newissue := issue.Issue{
					File:       "/home/src/project/test.go",
					Line:       "69-70",
					Col:        "14",
					RuleID:     rule,
					What:       "test",
					Confidence: issue.High,
					Severity:   issue.High,
					Cwe:        cwe,
					Suppressions: []issue.SuppressionInfo{
						{
							Kind:          "kind",
							Justification: "justification",
						},
					},
				}
				issues = append(issues, &newissue)
			}
			reportInfo := gosec.NewReportInfo(issues, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")

			sarifReport, err := sarif.GenerateReport([]string{}, reportInfo)

			Expect(err).ShouldNot(HaveOccurred())
			resultRuleIndexes := map[string]int{}
			for _, result := range sarifReport.Runs[0].Results {
				resultRuleIndexes[result.RuleID] = result.RuleIndex
			}
			driverRuleIndexes := map[string]int{}
			for ruleIndex, rule := range sarifReport.Runs[0].Tool.Driver.Rules {
				driverRuleIndexes[rule.ID] = ruleIndex
			}
			Expect(resultRuleIndexes).Should(Equal(driverRuleIndexes))
		})
	})
})
