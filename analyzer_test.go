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
			pkg.Build()

			err := analyzer.Process(buildTags, pkg.Path)
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
			pkg.Build()
			err := analyzer.Process(buildTags, pkg.Path)
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
			pkg1.Build()
			pkg2.Build()
			err := analyzer.Process(buildTags, pkg1.Path, pkg2.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, metrics, _ := analyzer.Report()
			Expect(metrics.NumFiles).To(Equal(2))
		})

		It("should find errors when nosec is not in use", func() {

			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			controlPackage := testutils.NewTestPackage()
			defer controlPackage.Close()
			controlPackage.AddFile("md5.go", source)
			controlPackage.Build()
			analyzer.Process(buildTags, controlPackage.Path)
			controlIssues, _, _ := analyzer.Report()
			Expect(controlIssues).Should(HaveLen(sample.Errors))

		})

		It("should report for Golang errors and invalid files", func() {
			analyzer.LoadRules(rules.Generate().Builders())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package main
				func main()
				}`)
			pkg.Build()
			err := analyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, golangErrors := analyzer.Report()
			keys := make([]string, len(golangErrors))
			i := 0
			for key := range golangErrors {
				keys[i] = key
				i++
			}
			fileErr := golangErrors[keys[0]]
			Expect(len(fileErr)).To(Equal(1))
			Expect(fileErr[0].Line).To(Equal(4))
			Expect(fileErr[0].Column).To(Equal(5))
			Expect(fileErr[0].Err).Should(MatchRegexp(`expected declaration, found '}'`))
		})

		It("should not report errors when a nosec comment is present", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			nosecPackage.Build()

			analyzer.Process(buildTags, nosecPackage.Path)
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
			nosecPackage.Build()

			analyzer.Process(buildTags, nosecPackage.Path)
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should report errors when an exclude comment is present for a different rule", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec G301", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			nosecPackage.Build()

			analyzer.Process(buildTags, nosecPackage.Path)
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
		})

		It("should not report errors when an exclude comment is present for multiple rules, including the correct rule", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec G301 G401", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			nosecPackage.Build()

			analyzer.Process(buildTags, nosecPackage.Path)
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
		nosecPackage.Build()

		customAnalyzer.Process(buildTags, nosecPackage.Path)
		nosecIssues, _, _ := customAnalyzer.Report()
		Expect(nosecIssues).Should(HaveLen(sample.Errors))

	})
})
