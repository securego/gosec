package gas_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ImportTracker", func() {
	var (
		source string
	)

	BeforeEach(func() {
		source = `// TODO(gm)`
	})
	Context("when I have a valid go package", func() {
		It("should record all import specs", func() {
            Expect(source).To(Equal(source))
			Skip("Not implemented")
		})

		It("should correctly track aliased package imports", func() {
			Skip("Not implemented")
		})

		It("should correctly track init only packages", func() {
			Skip("Not implemented")
		})
	})
})
