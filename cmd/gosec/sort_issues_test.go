package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
)

var defaultIssue = gosec.Issue{
	File:       "/home/src/project/test.go",
	Line:       "1",
	Col:        "1",
	RuleID:     "ruleID",
	What:       "test",
	Confidence: gosec.High,
	Severity:   gosec.High,
	Code:       "1: testcode",
	Cwe:        gosec.GetCweByRule("G101"),
}

func createIssue() gosec.Issue {
	return defaultIssue
}

func TestRules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sort issues Suite")
}

func firstIsGreater(less, greater *gosec.Issue) {
	slice := []*gosec.Issue{less, greater}

	sortIssues(slice)

	ExpectWithOffset(0, slice[0]).To(Equal(greater))
}

var _ = Describe("Sorting by Severity", func() {
	It("sorts by severity", func() {
		less := createIssue()
		less.Severity = gosec.Low
		greater := createIssue()
		less.Severity = gosec.High
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
	})
})
