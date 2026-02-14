package gosec_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

var _ = Describe("ReportInfo", func() {
	Describe("NewReportInfo", func() {
		It("should create a report with issues, metrics, and errors", func() {
			issues := []*issue.Issue{
				{RuleID: "G101", What: "test issue 1"},
				{RuleID: "G201", What: "test issue 2"},
			}
			metrics := &gosec.Metrics{
				NumFiles: 10,
				NumLines: 1000,
				NumNosec: 5,
				NumFound: 2,
			}
			errors := map[string][]gosec.Error{
				"file1.go": {{Line: 1, Column: 1, Err: "test error"}},
			}

			report := gosec.NewReportInfo(issues, metrics, errors)
			Expect(report).ShouldNot(BeNil())
			Expect(report.Issues).Should(HaveLen(2))
			Expect(report.Stats).Should(Equal(metrics))
			Expect(report.Errors).Should(HaveLen(1))
		})

		It("should handle empty issues", func() {
			metrics := &gosec.Metrics{}
			errors := map[string][]gosec.Error{}

			report := gosec.NewReportInfo([]*issue.Issue{}, metrics, errors)
			Expect(report).ShouldNot(BeNil())
			Expect(report.Issues).Should(BeEmpty())
		})

		It("should handle nil metrics and errors", func() {
			issues := []*issue.Issue{{RuleID: "G101"}}

			report := gosec.NewReportInfo(issues, nil, nil)
			Expect(report).ShouldNot(BeNil())
			Expect(report.Issues).Should(HaveLen(1))
			Expect(report.Stats).Should(BeNil())
			Expect(report.Errors).Should(BeNil())
		})
	})

	Describe("WithVersion", func() {
		It("should set the gosec version", func() {
			report := gosec.NewReportInfo([]*issue.Issue{}, &gosec.Metrics{}, nil)
			result := report.WithVersion("2.15.0")

			Expect(result).Should(BeIdenticalTo(report))
			Expect(report.GosecVersion).Should(Equal("2.15.0"))
		})

		It("should overwrite existing version", func() {
			report := gosec.NewReportInfo([]*issue.Issue{}, &gosec.Metrics{}, nil)
			report.WithVersion("1.0.0")
			report.WithVersion("2.0.0")

			Expect(report.GosecVersion).Should(Equal("2.0.0"))
		})

		It("should allow empty version string", func() {
			report := gosec.NewReportInfo([]*issue.Issue{}, &gosec.Metrics{}, nil)
			report.WithVersion("")

			Expect(report.GosecVersion).Should(Equal(""))
		})
	})
})
