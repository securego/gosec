package output

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec"
)

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
			want := sonarIssues{
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
			Expect(issues).To(Equal(want))
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
			want := sonarIssues{
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
			Expect(issues).To(Equal(want))
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
			want := sonarIssues{
				SonarIssues: nil,
			}

			rootPath := "/home/src/project2"

			issues, err := convertToSonarIssues([]string{rootPath}, data)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(issues).To(Equal(want))
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
			want := sonarIssues{
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
			Expect(issues).To(Equal(want))
		})
	})
})
