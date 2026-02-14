package gosec_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
)

var _ = Describe("Error", func() {
	Context("when creating errors", func() {
		It("should create a new error with correct fields", func() {
			err := gosec.NewError(10, 5, "test error message")
			Expect(err).ToNot(BeNil())
			Expect(err.Line).To(Equal(10))
			Expect(err.Column).To(Equal(5))
			Expect(err.Err).To(Equal("test error message"))
		})

		It("should handle zero values", func() {
			err := gosec.NewError(0, 0, "")
			Expect(err).ToNot(BeNil())
			Expect(err.Line).To(Equal(0))
			Expect(err.Column).To(Equal(0))
			Expect(err.Err).To(Equal(""))
		})

		It("should handle negative line and column numbers", func() {
			err := gosec.NewError(-1, -1, "negative values")
			Expect(err).ToNot(BeNil())
			Expect(err.Line).To(Equal(-1))
			Expect(err.Column).To(Equal(-1))
			Expect(err.Err).To(Equal("negative values"))
		})
	})
})
