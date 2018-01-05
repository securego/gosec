package gas_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/GoASTScanner/gas"
	"github.com/GoASTScanner/gas/rules"

	"github.com/GoASTScanner/gas/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Analyzer", func() {

	var (
		analyzer *gas.Analyzer
		logger   *log.Logger
		output   *bytes.Buffer
	)
	BeforeEach(func() {
		logger, output = testutils.NewLogger()
		analyzer = gas.NewAnalyzer(nil, logger)
	})

	Context("when processing a package", func() {

		It("should return an error if the package contains no Go files", func() {
			analyzer.LoadRules(rules.Generate().Builders()...)
			dir, err := ioutil.TempDir("", "empty")
			defer os.RemoveAll(dir)
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(dir)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(MatchRegexp("no buildable Go source files"))
		})

		It("should return an error if the package fails to build", func() {
			analyzer.LoadRules(rules.Generate().Builders()...)
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("wonky.go", `func main(){ println("forgot the package")}`)
			pkg.Build()

			err := analyzer.Process(pkg.Path)
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(MatchRegexp(`expected 'package'`))

		})

		It("should be able to analyze mulitple Go files", func() {
			analyzer.LoadRules(rules.Generate().Builders()...)
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
			err := analyzer.Process(pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, metrics := analyzer.Report()
			Expect(metrics.NumFiles).To(Equal(2))
		})

		It("should find errors when nosec is not in use", func() {

			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders()...)

			controlPackage := testutils.NewTestPackage()
			defer controlPackage.Close()
			controlPackage.AddFile("md5.go", source)
			controlPackage.Build()
			analyzer.Process(controlPackage.Path)
			controlIssues, _ := analyzer.Report()
			Expect(controlIssues).Should(HaveLen(sample.Errors))

		})

		It("should not report errors when a nosec comment is present", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders()...)

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			nosecPackage.Build()

			analyzer.Process(nosecPackage.Path)
			nosecIssues, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})
	})

	It("should be possible to overwrite nosec comments, and report issues", func() {

		// Rule for MD5 weak crypto usage
		sample := testutils.SampleCodeG401[0]
		source := sample.Code

		// overwrite nosec option
		nosecIgnoreConfig := gas.NewConfig()
		nosecIgnoreConfig.SetGlobal("nosec", "true")
		customAnalyzer := gas.NewAnalyzer(nosecIgnoreConfig, logger)
		customAnalyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, "G401")).Builders()...)

		nosecPackage := testutils.NewTestPackage()
		defer nosecPackage.Close()
		nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #nosec", 1)
		nosecPackage.AddFile("md5.go", nosecSource)
		nosecPackage.Build()

		customAnalyzer.Process(nosecPackage.Path)
		nosecIssues, _ := customAnalyzer.Report()
		Expect(nosecIssues).Should(HaveLen(sample.Errors))

	})
})
