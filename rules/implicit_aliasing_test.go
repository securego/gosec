package rules

import (
. "github.com/onsi/ginkgo/v2"
. "github.com/onsi/gomega"

"github.com/securego/gosec/v2"
)

var _ = Describe("NewImplicitAliasing", func() {
	It("should create rule for detecting implicit memory aliasing", func() {
		config := gosec.NewConfig()
		rule, nodes := NewImplicitAliasing("G601", config)

		Expect(rule).ShouldNot(BeNil())
		Expect(nodes).ShouldNot(BeEmpty())
		Expect(rule.ID()).Should(Equal("G601"))
		Expect(nodes).Should(HaveLen(3)) // RangeStmt, UnaryExpr, ReturnStmt
	})

	It("should initialize with correct metadata", func() {
		config := gosec.NewConfig()
		rule, _ := NewImplicitAliasing("G601", config)

		Expect(rule.ID()).Should(Equal("G601"))
	})
})
