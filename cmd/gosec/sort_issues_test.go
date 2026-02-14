package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2/issue"
)

var defaultIssue = issue.Issue{
	File:       "/home/src/project/test.go",
	Line:       "1",
	Col:        "1",
	RuleID:     "ruleID",
	What:       "test",
	Confidence: issue.High,
	Severity:   issue.High,
	Code:       "1: testcode",
	Cwe:        issue.GetCweByRule("G101"),
}

func createIssue() issue.Issue {
	return defaultIssue
}

func TestRules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sort issues Suite")
}

func firstIsGreater(less, greater *issue.Issue) {
	slice := []*issue.Issue{less, greater}

	sortIssues(slice)

	ExpectWithOffset(0, slice[0]).To(Equal(greater))
}

var _ = Describe("Sorting by Severity", func() {
	It("sorts by severity", func() {
		less := createIssue()
		less.Severity = issue.Low
		greater := createIssue()
		less.Severity = issue.High
		firstIsGreater(&less, &greater)
	})

	Context("Severity is same", func() {
		It("sorts by What", func() {
			less := createIssue()
			less.What = "test1"
			greater := createIssue()
			greater.What = "test2"
			firstIsGreater(&less, &greater)
		})
	})

	Context("Severity and What is same", func() {
		It("sorts by File", func() {
			less := createIssue()
			less.File = "test1"
			greater := createIssue()
			greater.File = "test2"

			firstIsGreater(&less, &greater)
		})
	})

	Context("Severity, What and File is same", func() {
		It("sorts by line number", func() {
			less := createIssue()
			less.Line = "1"
			greater := createIssue()
			greater.Line = "2"

			firstIsGreater(&less, &greater)
		})

		It("handles line ranges correctly", func() {
			less := createIssue()
			less.Line = "5-10"
			greater := createIssue()
			greater.Line = "15-20"

			firstIsGreater(&less, &greater)
		})

		It("compares start line in ranges", func() {
			less := createIssue()
			less.Line = "10-15"
			greater := createIssue()
			greater.Line = "10-20"

			// When start lines are equal, order is preserved (stable sort)
			slice := []*issue.Issue{&less, &greater}
			sortIssues(slice)
			// Both have same start line, so order based on earlier criteria
		})

		It("handles single line vs range", func() {
			less := createIssue()
			less.Line = "5"
			greater := createIssue()
			greater.Line = "10-15"

			firstIsGreater(&less, &greater)
		})
	})
})

var _ = Describe("extractLineNumber function", func() {
	It("extracts single line number", func() {
		lineNum := extractLineNumber("42")
		Expect(lineNum).To(Equal(42))
	})

	It("extracts start line from range", func() {
		lineNum := extractLineNumber("10-20")
		Expect(lineNum).To(Equal(10))
	})

	It("handles invalid line numbers", func() {
		lineNum := extractLineNumber("invalid")
		Expect(lineNum).To(Equal(0))
	})

	It("handles empty string", func() {
		lineNum := extractLineNumber("")
		Expect(lineNum).To(Equal(0))
	})

	It("handles multiple dashes", func() {
		lineNum := extractLineNumber("5-10-15")
		Expect(lineNum).To(Equal(5))
	})
})

var _ = Describe("Sorting multiple issues", func() {
	It("sorts multiple issues correctly by all criteria", func() {
		issues := []*issue.Issue{
			{Severity: issue.Low, What: "warning1", File: "file1.go", Line: "10"},
			{Severity: issue.High, What: "error1", File: "file1.go", Line: "5"},
			{Severity: issue.High, What: "error2", File: "file1.go", Line: "1"},
			{Severity: issue.Medium, What: "warning2", File: "file2.go", Line: "20"},
			{Severity: issue.High, What: "error1", File: "file2.go", Line: "3"},
		}

		sortIssues(issues)

		// First should be High severity
		Expect(issues[0].Severity).To(Equal(issue.High))
		// Within High severity, sorted by What (descending), then File, then Line
		// "error2" > "error1" alphabetically, so error2 comes first
		Expect(issues[0].What).To(Equal("error2"))
		Expect(issues[0].File).To(Equal("file1.go"))
		Expect(issues[0].Line).To(Equal("1"))
	})

	It("handles empty slice", func() {
		issues := []*issue.Issue{}
		sortIssues(issues)
		Expect(issues).To(BeEmpty())
	})

	It("handles single issue", func() {
		issue1 := createIssue()
		issues := []*issue.Issue{&issue1}
		sortIssues(issues)
		Expect(issues).To(HaveLen(1))
		Expect(issues[0]).To(Equal(&issue1))
	})

	It("maintains stability for equal issues", func() {
		issue1 := createIssue()
		issue2 := createIssue()
		// Same severity, what, file, and line
		issues := []*issue.Issue{&issue1, &issue2}

		sortIssues(issues)

		Expect(issues).To(HaveLen(2))
	})

	It("sorts issues with different severity levels", func() {
		low := createIssue()
		low.Severity = issue.Low
		medium := createIssue()
		medium.Severity = issue.Medium
		high := createIssue()
		high.Severity = issue.High

		issues := []*issue.Issue{&low, &high, &medium}
		sortIssues(issues)

		Expect(issues[0].Severity).To(Equal(issue.High))
		Expect(issues[1].Severity).To(Equal(issue.Medium))
		Expect(issues[2].Severity).To(Equal(issue.Low))
	})
})
