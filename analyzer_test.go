package gosec_test

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/securego/gosec"
	"github.com/securego/gosec/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/testutils"
)

var _ = Describe("Analyzer", func() {

	var (
		analyzer  *gosec.Analyzer
		logger    *log.Logger
		buildTags []string
		tests     bool
	)
	BeforeEach(func() {
		logger, _ = testutils.NewLogger()
		analyzer = gosec.NewAnalyzer(nil, tests, logger)
	})

	Context("when processing a package", func() {

		It("should return an error if the package contains no Go files", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			dir, err := ioutil.TempDir("", "empty")
			defer os.RemoveAll(dir)
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, dir)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(MatchRegexp("no buildable Go source files"))
		})

		It("should return an error if the package fails to build", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("wonky.go", `func main(){ println("forgot the package")}`)
			err := pkg.Build()
			Expect(err).Should(HaveOccurred())
			err = analyzer.Process(buildTags, pkg.Path)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(MatchRegexp(`expected 'package'`))

		})

		It("should be able to analyze multiple Go files", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package main
				func main(){
					bar()
				}`)
			pkg.AddFile("bar.go", `
				package main
				func bar(){
					println("package has two files!")
				}`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, metrics, _ := analyzer.Report()
			Expect(metrics.NumFiles).To(Equal(2))
		})

		It("should be able to analyze multiple Go packages", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg1 := testutils.NewTestPackage()
			pkg2 := testutils.NewTestPackage()
			defer pkg1.Close()
			defer pkg2.Close()
			pkg1.AddFile("foo.go", `
				package main
				func main(){
				}`)
			pkg2.AddFile("bar.go", `
				package main
				func bar(){
				}`)
			err := pkg1.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = pkg2.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, pkg1.Path, pkg2.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, metrics, _ := analyzer.Report()
			Expect(metrics.NumFiles).To(Equal(2))
		})

		It("should find errors when nosec is not in use", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			controlPackage := testutils.NewTestPackage()
			defer controlPackage.Close()
			controlPackage.AddFile("md5.go", source)
			err := controlPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, controlPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			controlIssues, _, _ := analyzer.Report()
			Expect(controlIssues).Should(HaveLen(sample.Errors))

		})

		It("should report Go build errors and invalid files", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package main
				func main()
				}`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(1))
				Expect(ferr[0].Line).To(Equal(4))
				Expect(ferr[0].Column).To(Equal(5))
				Expect(ferr[0].Err).Should(MatchRegexp(`expected declaration, found '}'`))
			}
		})

		It("should not report errors when a nosec comment is present", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should not report errors when an exclude comment is present for the correct rule", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec G401", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should report errors when an exclude comment is present for a different rule", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec G301", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
		})

		It("should not report errors when an exclude comment is present for multiple rules, including the correct rule", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec G301 G401", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should pass the build tags", func() {
			sample := testutils.SampleCode601[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("tags.go", source)
			buildTags = append(buildTags, "test")
			err := analyzer.Process(buildTags, pkg.Path)
			Expect(err).Should(HaveOccurred())
		})

		It("should process an empty package with test file", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo_test.go", `
                package tests
			    import "testing"
			    func TestFoo(t *testing.T){
			    }`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
		})
		It("should report an error when the package is empty", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			err := analyzer.Process(buildTags, pkg.Path)
			Expect(err).Should(HaveOccurred())
		})
	})

	It("should be possible to overwrite nosec comments, and report issues", func() {
		// Rule for MD5 weak crypto usage
		sample := testutils.SampleCodeG401[0]
		source := sample.Code[0]

		// overwrite nosec option
		nosecIgnoreConfig := gosec.NewConfig()
		nosecIgnoreConfig.SetGlobal(gosec.Nosec, "true")
		customAnalyzer := gosec.NewAnalyzer(nosecIgnoreConfig, tests, logger)
		customAnalyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

		nosecPackage := testutils.NewTestPackage()
		defer nosecPackage.Close()
		nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec", 1)
		nosecPackage.AddFile("md5.go", nosecSource)
		err := nosecPackage.Build()
		Expect(err).ShouldNot(HaveOccurred())
		err = customAnalyzer.Process(buildTags, nosecPackage.Path)
		Expect(err).ShouldNot(HaveOccurred())
		nosecIssues, _, _ := customAnalyzer.Report()
		Expect(nosecIssues).Should(HaveLen(sample.Errors))

	})

	It("should be able to analyze Go test package", func() {
		customAnalyzer := gosec.NewAnalyzer(nil, true, logger)
		customAnalyzer.LoadRules(rules.Generate().Builders())
		pkg := testutils.NewTestPackage()
		defer pkg.Close()
		pkg.AddFile("foo.go", `
			package foo
			func foo(){
			}`)
		pkg.AddFile("foo_test.go", `
			package foo_test
			import "testing"
			func TestFoo(t *testing.T){
			}`)
		err := pkg.Build()
		Expect(err).ShouldNot(HaveOccurred())
		err = customAnalyzer.Process(buildTags, pkg.Path)
		Expect(err).ShouldNot(HaveOccurred())
		_, metrics, _ := customAnalyzer.Report()
		Expect(metrics.NumFiles).To(Equal(3))
	})
})
