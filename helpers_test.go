package gosec_test

import (
	"io/ioutil"
	"os"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec"
)

var _ = Describe("Helpers", func() {
	Context("when listing pacakge paths", func() {
		var dir string
		JustBeforeEach(func() {
			var err error
			dir, err = ioutil.TempDir("", "gosec")
			Expect(err).ShouldNot(HaveOccurred())
			_, err = ioutil.TempFile(dir, "test*.go")
			Expect(err).ShouldNot(HaveOccurred())
		})
		AfterEach(func() {
			err := os.RemoveAll(dir)
			Expect(err).ShouldNot(HaveOccurred())
		})
		It("should return the root directory as package path", func() {
			paths, err := gosec.PackagePaths(dir, nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should return the package package path", func() {
			paths, err := gosec.PackagePaths(dir+"/...", nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should exclude folder", func() {
			nested := dir + "/vendor"
			err := os.Mkdir(nested, 0755)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = os.Create(nested + "/test.go")
			Expect(err).ShouldNot(HaveOccurred())
			exclude, err := regexp.Compile(`([\\/])?vendor([\\/])?`)
			Expect(err).ShouldNot(HaveOccurred())
			paths, err := gosec.PackagePaths(dir+"/...", exclude)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should be empty when folder does not exist", func() {
			nested := dir + "/test"
			paths, err := gosec.PackagePaths(nested+"/...", nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(BeEmpty())
		})
	})
})
