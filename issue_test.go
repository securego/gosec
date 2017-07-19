package gas_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Issue", func() {

	Context("when creating a new issue", func() {
		It("should provide a code snippet for the specified ast.Node", func() {
			Expect(1).Should(Equal(2))
			Fail("Not implemented")
		})

		It("should return an error if specific context is not able to be obtained", func() {
			Fail("Not implemented")
		})

		It("should provide accurate line and file information", func() {
			Fail("Not implemented")
		})

		It("should maintain the provided severity score", func() {
			Fail("Not implemented")
		})

		It("should maintain the provided confidence score", func() {
			Fail("Not implemented")
		})

		It("should correctly record `unsafe` import as not considered a package", func() {
			Fail("Not implemented")
		})
	})

})
