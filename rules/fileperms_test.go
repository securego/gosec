package rules

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
)

var _ = Describe("modeIsSubset", func() {
	It("it compares modes correctly", func() {
		Expect(modeIsSubset(0o600, 0o600)).To(BeTrue())
		Expect(modeIsSubset(0o400, 0o600)).To(BeTrue())
		Expect(modeIsSubset(0o644, 0o600)).To(BeFalse())
		Expect(modeIsSubset(0o466, 0o600)).To(BeFalse())
	})
})

var _ = Describe("NewOsCreatePerms", func() {
	It("should create rule with default permissions", func() {
		config := gosec.NewConfig()
		rule, nodes := NewOsCreatePerms("G306", config)

		Expect(rule).ShouldNot(BeNil())
		Expect(nodes).ShouldNot(BeEmpty())
		Expect(rule.ID()).Should(Equal("G306"))
	})

	It("should create rule with custom permissions from config", func() {
		config := gosec.NewConfig()
		config["G306"] = map[string]interface{}{
			"mode": "0600",
		}
		rule, nodes := NewOsCreatePerms("G306", config)

		Expect(rule).ShouldNot(BeNil())
		Expect(nodes).ShouldNot(BeEmpty())
		Expect(rule.ID()).Should(Equal("G306"))
	})
})
