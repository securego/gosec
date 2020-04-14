package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
	"gopkg.in/yaml.v2"
)

func createIssue(ruleID string, cwe gosec.Cwe) gosec.Issue {
	return gosec.Issue{
		File:       "/home/src/project/test.go",
		Line:       "1",
		Col:        "1",
		RuleID:     ruleID,
		What:       "test",
		Confidence: gosec.High,
		Severity:   gosec.High,
		Code:       "testcode",
		Cwe:        cwe,
	}
}

func createReportInfo(rule string, cwe gosec.Cwe) reportInfo {
	issue := createIssue(rule, cwe)
	metrics := gosec.Metrics{}
	return reportInfo{
		Errors: map[string][]gosec.Error{},
		Issues: []*gosec.Issue{
			&issue,
		},
		Stats: &metrics,
	}
}

func stripString(str string) string {
	ret := strings.Replace(str, "\n", "", -1)
	ret = strings.Replace(ret, " ", "", -1)
	ret = strings.Replace(ret, "\t", "", -1)
	return ret
}

var _ = Describe("Formatter", func() {
	BeforeEach(func() {
	})
	Context("when converting to Sonarqube issues", func() {
		It("it should parse the report info", func() {
			data := &reportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*gosec.Issue{
					&gosec.Issue{
						Severity:   2,
						Confidence: 0,
						RuleID:     "test",
						What:       "test",
						File:       "/home/src/project/test.go",
						Code:       "",
						Line:       "1-2",
					},
				},
				Stats: &gosec.Metrics{
					NumFiles: 0,
					NumLines: 0,
					NumNosec: 0,
					NumFound: 0,
				},
			}
			want := &sonarIssues{
				SonarIssues: []sonarIssue{
					{
						EngineID: "gosec",
						RuleID:   "test",
						PrimaryLocation: location{
							Message:  "test",
							FilePath: "test.go",
							TextRange: textRange{
								StartLine: 1,
								EndLine:   2,
							},
						},
						Type:          "VULNERABILITY",
						Severity:      "BLOCKER",
						EffortMinutes: SonarqubeEffortMinutes,
					},
				},
			}

			rootPath := "/home/src/project"

			issues, err := convertToSonarIssues([]string{rootPath}, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*issues).To(Equal(*want))
		})

		It("it should parse the report info with files in subfolders", func() {
			data := &reportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*gosec.Issue{
					&gosec.Issue{
						Severity:   2,
						Confidence: 0,
						RuleID:     "test",
						What:       "test",
						File:       "/home/src/project/subfolder/test.go",
						Code:       "",
						Line:       "1-2",
					},
				},
				Stats: &gosec.Metrics{
					NumFiles: 0,
					NumLines: 0,
					NumNosec: 0,
					NumFound: 0,
				},
			}
			want := &sonarIssues{
				SonarIssues: []sonarIssue{
					{
						EngineID: "gosec",
						RuleID:   "test",
						PrimaryLocation: location{
							Message:  "test",
							FilePath: "subfolder/test.go",
							TextRange: textRange{
								StartLine: 1,
								EndLine:   2,
							},
						},
						Type:          "VULNERABILITY",
						Severity:      "BLOCKER",
						EffortMinutes: SonarqubeEffortMinutes,
					},
				},
			}

			rootPath := "/home/src/project"

			issues, err := convertToSonarIssues([]string{rootPath}, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*issues).To(Equal(*want))
		})
		It("it should not parse the report info for files from other projects", func() {
			data := &reportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*gosec.Issue{
					&gosec.Issue{
						Severity:   2,
						Confidence: 0,
						RuleID:     "test",
						What:       "test",
						File:       "/home/src/project1/test.go",
						Code:       "",
						Line:       "1-2",
					},
				},
				Stats: &gosec.Metrics{
					NumFiles: 0,
					NumLines: 0,
					NumNosec: 0,
					NumFound: 0,
				},
			}
			want := &sonarIssues{
				SonarIssues: []sonarIssue{},
			}

			rootPath := "/home/src/project2"

			issues, err := convertToSonarIssues([]string{rootPath}, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*issues).To(Equal(*want))
		})

		It("it should parse the report info for multiple projects projects", func() {
			data := &reportInfo{
				Errors: map[string][]gosec.Error{},
				Issues: []*gosec.Issue{
					&gosec.Issue{
						Severity:   2,
						Confidence: 0,
						RuleID:     "test",
						What:       "test",
						File:       "/home/src/project1/test-project1.go",
						Code:       "",
						Line:       "1-2",
					},
					&gosec.Issue{
						Severity:   2,
						Confidence: 0,
						RuleID:     "test",
						What:       "test",
						File:       "/home/src/project2/test-project2.go",
						Code:       "",
						Line:       "1-2",
					},
				},
				Stats: &gosec.Metrics{
					NumFiles: 0,
					NumLines: 0,
					NumNosec: 0,
					NumFound: 0,
				},
			}
			want := &sonarIssues{
				SonarIssues: []sonarIssue{
					{
						EngineID: "gosec",
						RuleID:   "test",
						PrimaryLocation: location{
							Message:  "test",
							FilePath: "test-project1.go",
							TextRange: textRange{
								StartLine: 1,
								EndLine:   2,
							},
						},
						Type:          "VULNERABILITY",
						Severity:      "BLOCKER",
						EffortMinutes: SonarqubeEffortMinutes,
					},
					{
						EngineID: "gosec",
						RuleID:   "test",
						PrimaryLocation: location{
							Message:  "test",
							FilePath: "test-project2.go",
							TextRange: textRange{
								StartLine: 1,
								EndLine:   2,
							},
						},
						Type:          "VULNERABILITY",
						Severity:      "BLOCKER",
						EffortMinutes: SonarqubeEffortMinutes,
					},
				},
			}

			rootPaths := []string{"/home/src/project1", "/home/src/project2"}

			issues, err := convertToSonarIssues(rootPaths, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(*issues).To(Equal(*want))
		})
	})
	Context("When using different report formats", func() {

		grules := []string{"G101", "G102", "G103", "G104", "G106",
			"G107", "G109", "G110", "G201", "G202", "G203", "G204",
			"G301", "G302", "G303", "G304", "G305", "G401", "G402",
			"G403", "G404", "G501", "G502", "G503", "G504", "G505"}

		It("csv formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				buf := new(bytes.Buffer)
				err := CreateReport(buf, "csv", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				pattern := "/home/src/project/test.go,1,test,HIGH,HIGH,testcode,CWE-%s\n"
				expect := fmt.Sprintf(pattern, cwe.ID)
				Expect(string(buf.String())).To(Equal(expect))
			}
		})
		It("xml formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				buf := new(bytes.Buffer)
				err := CreateReport(buf, "xml", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{NumFiles: 0, NumLines: 0, NumNosec: 0, NumFound: 0}, error)
				Expect(err).ShouldNot(HaveOccurred())
				pattern := "Results:\n\n\n[/home/src/project/test.go:1] - %s (CWE-%s): test (Confidence: HIGH, Severity: HIGH)\n  > testcode\n\n\nSummary:\n   Files: 0\n   Lines: 0\n   Nosec: 0\n  Issues: 0\n\n"
				expect := fmt.Sprintf(pattern, rule, cwe.ID)
				Expect(string(buf.String())).To(Equal(expect))
			}
		})
		It("json formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				data := createReportInfo(rule, cwe)

				expect := new(bytes.Buffer)
				enc := json.NewEncoder(expect)
				err := enc.Encode(data)
				Expect(err).ShouldNot(HaveOccurred())
				buf := new(bytes.Buffer)
				err = CreateReport(buf, "json", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				result := stripString(buf.String())
				expectation := stripString(expect.String())
				Expect(result).To(Equal(expectation))
			}
		})
		It("html formatted report should  contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				data := createReportInfo(rule, cwe)

				expect := new(bytes.Buffer)
				enc := json.NewEncoder(expect)
				err := enc.Encode(data)
				Expect(err).ShouldNot(HaveOccurred())
				buf := new(bytes.Buffer)
				err = CreateReport(buf, "html", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				result := stripString(buf.String())
				expectation := stripString(expect.String())
				Expect(result).To(ContainSubstring(expectation))
			}
		})
		It("yaml formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				data := createReportInfo(rule, cwe)

				expect := new(bytes.Buffer)
				enc := yaml.NewEncoder(expect)
				err := enc.Encode(data)
				Expect(err).ShouldNot(HaveOccurred())
				buf := new(bytes.Buffer)
				err = CreateReport(buf, "yaml", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				result := stripString(buf.String())
				expectation := stripString(expect.String())
				Expect(result).To(ContainSubstring(expectation))
			}
		})
		It("junit-xml formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				data := createReportInfo(rule, cwe)

				expect := new(bytes.Buffer)
				enc := yaml.NewEncoder(expect)
				err := enc.Encode(data)
				Expect(err).ShouldNot(HaveOccurred())
				buf := new(bytes.Buffer)
				err = CreateReport(buf, "junit-xml", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				expectation := stripString(fmt.Sprintf("[/home/src/project/test.go:1] - test (Confidence: 2, Severity: 2, CWE: %s)", cwe.ID))
				result := stripString(buf.String())
				Expect(result).To(ContainSubstring(expectation))
			}
		})
		It("text formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				data := createReportInfo(rule, cwe)

				expect := new(bytes.Buffer)
				enc := yaml.NewEncoder(expect)
				err := enc.Encode(data)
				Expect(err).ShouldNot(HaveOccurred())
				buf := new(bytes.Buffer)
				err = CreateReport(buf, "text", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				expectation := stripString(fmt.Sprintf("[/home/src/project/test.go:1] - %s (CWE-%s): test (Confidence: HIGH, Severity: HIGH)", rule, cwe.ID))
				result := stripString(buf.String())
				Expect(result).To(ContainSubstring(expectation))
			}
		})
		It("sonarqube formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}
				buf := new(bytes.Buffer)
				err := CreateReport(buf, "sonarqube", false, []string{"/home/src/project"}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())

				result := stripString(buf.String())

				expect := new(bytes.Buffer)
				enc := json.NewEncoder(expect)
				err = enc.Encode(cwe)
				Expect(err).ShouldNot(HaveOccurred())

				expectation := stripString(expect.String())
				Expect(result).To(ContainSubstring(expectation))
			}
		})
		It("golint formatted report should contain the CWE mapping", func() {
			for _, rule := range grules {
				cwe := gosec.IssueToCWE[rule]
				issue := createIssue(rule, cwe)
				error := map[string][]gosec.Error{}

				buf := new(bytes.Buffer)
				err := CreateReport(buf, "golint", false, []string{}, []*gosec.Issue{&issue}, &gosec.Metrics{}, error)
				Expect(err).ShouldNot(HaveOccurred())
				pattern := "/home/src/project/test.go:1:1: [CWE-%s] test (Rule:%s, Severity:HIGH, Confidence:HIGH)\n"
				expect := fmt.Sprintf(pattern, cwe.ID, rule)
				Expect(string(buf.String())).To(Equal(expect))
			}
		})
	})
})
