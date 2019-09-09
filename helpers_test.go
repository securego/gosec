package gosec_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
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
			paths, err := gosec.PackagePaths(dir+"/...", []*regexp.Regexp{exclude})
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

	Context("when getting the root path", func() {
		It("should return the absolute path from relative path", func() {
			base := "test"
			cwd, err := os.Getwd()
			Expect(err).ShouldNot(HaveOccurred())
			root, err := gosec.RootPath(base)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(root).Should(Equal(filepath.Join(cwd, base)))
		})
		It("should retrun the absolute path from ellipsis path", func() {
			base := "test"
			cwd, err := os.Getwd()
			Expect(err).ShouldNot(HaveOccurred())
			root, err := gosec.RootPath(filepath.Join(base, "..."))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(root).Should(Equal(filepath.Join(cwd, base)))
		})
	})

	Context("when excluding the dirs", func() {
		It("should create a proper regexp", func() {
			r := gosec.ExcludedDirsRegExp([]string{"test"})
			Expect(len(r)).Should(Equal(1))
			match := r[0].MatchString("/home/go/src/project/test/pkg")
			Expect(match).Should(BeTrue())
			match = r[0].MatchString("/home/go/src/project/vendor/pkg")
			Expect(match).Should(BeFalse())
		})

		It("should create no regexp when dir list is empty", func() {
			r := gosec.ExcludedDirsRegExp(nil)
			Expect(len(r)).Should(Equal(0))
			r = gosec.ExcludedDirsRegExp([]string{})
			Expect(len(r)).Should(Equal(0))
		})
	})
})
