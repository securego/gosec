package gosec_test

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
	"github.com/securego/gosec/v2/testutils"
	"golang.org/x/tools/go/packages"
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
		analyzer = gosec.NewAnalyzer(nil, tests, false, false, 1, logger)
	})

	Context("when processing a package", func() {
		It("should not report an error if the package contains no Go files", func() {
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
			dir, err := ioutil.TempDir("", "empty")
			defer os.RemoveAll(dir)
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, dir)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(0))
		})

		It("should report an error if the package fails to build", func() {
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("wonky.go", `func main(){ println("forgot the package")}`)
			err := pkg.Build()
			Expect(err).Should(HaveOccurred())
			err = analyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(1))
			}
		})

		It("should be able to analyze multiple Go files", func() {
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
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

		It("should be able to analyze multiple Go files concurrently", func() {
			customAnalyzer := gosec.NewAnalyzer(nil, true, true, false, 32, logger)
			customAnalyzer.LoadRules(rules.Generate(false).RulesInfo())
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
			err = customAnalyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			_, metrics, _ := customAnalyzer.Report()
			Expect(metrics.NumFiles).To(Equal(2))
		})

		It("should be able to analyze multiple Go packages", func() {
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
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
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

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
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
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

		It("should not report errors when a nosec line comment is present", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should not report errors when a nosec block comment is present", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() /* #nosec */", 1)
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
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec G401", 1)
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
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec G301", 1)
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
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec G301 G401", 1)
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
			sample := testutils.SampleCodeBuildTag[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("tags.go", source)
			tags := []string{"tag"}
			err := analyzer.Process(tags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should process an empty package with test file", func() {
			analyzer.LoadRules(rules.Generate(false).RulesInfo())
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

		It("should be possible to overwrite nosec comments, and report issues", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]

			// overwrite nosec option
			nosecIgnoreConfig := gosec.NewConfig()
			nosecIgnoreConfig.SetGlobal(gosec.Nosec, "true")
			customAnalyzer := gosec.NewAnalyzer(nosecIgnoreConfig, tests, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := customAnalyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
		})

		XIt("should be possible to overwrite nosec comments, and report issues but the should not be counted", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]

			// overwrite nosec option
			nosecIgnoreConfig := gosec.NewConfig()
			nosecIgnoreConfig.SetGlobal(gosec.Nosec, "true")
			nosecIgnoreConfig.SetGlobal(gosec.ShowIgnored, "true")
			customAnalyzer := gosec.NewAnalyzer(nosecIgnoreConfig, tests, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, metrics, _ := customAnalyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
			Expect(metrics.NumFound).Should(Equal(0))
			Expect(metrics.NumNosec).Should(Equal(1))
		})

		It("should not report errors when nosec tag is in front of a line", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "//Some description\n//#nosec G401\nh := md5.New()", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should report errors when nosec tag is not in front of a line", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "//Some description\n//Another description #nosec G401\nh := md5.New()", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
		})

		It("should not report errors when rules are in front of nosec tag even rules are wrong", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "//G301\n//#nosec\nh := md5.New()", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(BeEmpty())
		})

		It("should report errors when there are nosec tags after a #nosec WrongRuleList annotation", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "//#nosec\n//G301\n//#nosec\nh := md5.New()", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := analyzer.Report()
			Expect(nosecIssues).Should(HaveLen(sample.Errors))
		})

		It("should be possible to use an alternative nosec tag", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]

			// overwrite nosec option
			nosecIgnoreConfig := gosec.NewConfig()
			nosecIgnoreConfig.SetGlobal(gosec.NoSecAlternative, "#falsePositive")
			customAnalyzer := gosec.NewAnalyzer(nosecIgnoreConfig, tests, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() // #falsePositive", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := customAnalyzer.Report()
			Expect(nosecIssues).Should(HaveLen(0))
		})

		It("should ignore vulnerabilities when the default tag is found", func() {
			// Rule for MD5 weak crypto usage
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]

			// overwrite nosec option
			nosecIgnoreConfig := gosec.NewConfig()
			nosecIgnoreConfig.SetGlobal(gosec.NoSecAlternative, "#falsePositive")
			customAnalyzer := gosec.NewAnalyzer(nosecIgnoreConfig, tests, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			nosecIssues, _, _ := customAnalyzer.Report()
			Expect(nosecIssues).Should(HaveLen(0))
		})

		It("should be able to analyze Go test package", func() {
			customAnalyzer := gosec.NewAnalyzer(nil, true, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false).RulesInfo())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package foo
				func foo(){
				}`)
			pkg.AddFile("foo_test.go", `
				package foo_test
				import "testing"
				func test() error {
				  return nil
				}
				func TestFoo(t *testing.T){
					test()
				}`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := customAnalyzer.Report()
			Expect(issues).Should(HaveLen(1))
		})
		It("should be able to scan generated files if NOT excluded", func() {
			customAnalyzer := gosec.NewAnalyzer(nil, true, false, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false).RulesInfo())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package foo
				// Code generated some-generator DO NOT EDIT.
				func test() error {
				  return nil
				}
				func TestFoo(t *testing.T){
					test()
				}`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := customAnalyzer.Report()
			Expect(issues).Should(HaveLen(1))
		})
		It("should be able to skip generated files if excluded", func() {
			customAnalyzer := gosec.NewAnalyzer(nil, true, true, false, 1, logger)
			customAnalyzer.LoadRules(rules.Generate(false).RulesInfo())
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `
				package foo
				// Code generated some-generator DO NOT EDIT.
				func test() error {
				  return nil
				}
				func TestFoo(t *testing.T){
					test()
				}`)
			err := pkg.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = customAnalyzer.Process(buildTags, pkg.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := customAnalyzer.Report()
			Expect(issues).Should(HaveLen(0))
		})
	})
	It("should be able to analyze Cgo files", func() {
		analyzer.LoadRules(rules.Generate(false).RulesInfo())
		sample := testutils.SampleCodeCgo[0]
		source := sample.Code[0]

		testPackage := testutils.NewTestPackage()
		defer testPackage.Close()
		testPackage.AddFile("main.go", source)
		err := testPackage.Build()
		Expect(err).ShouldNot(HaveOccurred())
		err = analyzer.Process(buildTags, testPackage.Path)
		Expect(err).ShouldNot(HaveOccurred())
		issues, _, _ := analyzer.Report()
		Expect(issues).Should(HaveLen(0))
	})

	Context("when parsing errors from a package", func() {
		It("should return no error when the error list is empty", func() {
			pkg := &packages.Package{}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should properly parse the errors", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file:1:2",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(1))
				Expect(ferr[0].Line).To(Equal(1))
				Expect(ferr[0].Column).To(Equal(2))
				Expect(ferr[0].Err).Should(MatchRegexp(`build error`))
			}
		})

		It("should properly parse the errors without line and column", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(1))
				Expect(ferr[0].Line).To(Equal(0))
				Expect(ferr[0].Column).To(Equal(0))
				Expect(ferr[0].Err).Should(MatchRegexp(`build error`))
			}
		})

		It("should properly parse the errors without column", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(1))
				Expect(ferr[0].Line).To(Equal(0))
				Expect(ferr[0].Column).To(Equal(0))
				Expect(ferr[0].Err).Should(MatchRegexp(`build error`))
			}
		})

		It("should return error when line cannot be parsed", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file:line",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).Should(HaveOccurred())
		})

		It("should return error when column cannot be parsed", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file:1:column",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).Should(HaveOccurred())
		})

		It("should append  error to the same file", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file:1:2",
						Msg: "error1",
					},
					{
						Pos: "file:3:4",
						Msg: "error2",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(2))
				Expect(ferr[0].Line).To(Equal(1))
				Expect(ferr[0].Column).To(Equal(2))
				Expect(ferr[0].Err).Should(MatchRegexp(`error1`))
				Expect(ferr[1].Line).To(Equal(3))
				Expect(ferr[1].Column).To(Equal(4))
				Expect(ferr[1].Err).Should(MatchRegexp(`error2`))
			}
		})

		It("should set the config", func() {
			config := gosec.NewConfig()
			config["test"] = "test"
			analyzer.SetConfig(config)
			found := analyzer.Config()
			Expect(config).To(Equal(found))
		})

		It("should reset the analyzer", func() {
			analyzer.Reset()
			issues, metrics, errors := analyzer.Report()
			Expect(issues).To(BeEmpty())
			Expect(*metrics).To(Equal(gosec.Metrics{}))
			Expect(errors).To(BeEmpty())
		})
	})

	Context("when appending errors", func() {
		It("should skip error for non-buildable packages", func() {
			analyzer.AppendError("test", errors.New(`loading file from package "pkg/test": no buildable Go source files in pkg/test`))
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(0))
		})

		It("should add a new error", func() {
			pkg := &packages.Package{
				Errors: []packages.Error{
					{
						Pos: "file:1:2",
						Msg: "build error",
					},
				},
			}
			err := analyzer.ParseErrors(pkg)
			Expect(err).ShouldNot(HaveOccurred())
			analyzer.AppendError("file", errors.New("file build error"))
			_, _, errors := analyzer.Report()
			Expect(len(errors)).To(Equal(1))
			for _, ferr := range errors {
				Expect(len(ferr)).To(Equal(2))
			}
		})
	})

	Context("when tracking suppressions", func() {
		BeforeEach(func() {
			analyzer = gosec.NewAnalyzer(nil, tests, false, true, 1, logger)
		})

		It("should not report an error if the violation is suppressed", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec G401 -- Justification", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := analyzer.Report()
			Expect(issues).To(HaveLen(sample.Errors))
			Expect(issues[0].Suppressions).To(HaveLen(1))
			Expect(issues[0].Suppressions[0].Kind).To(Equal("inSource"))
			Expect(issues[0].Suppressions[0].Justification).To(Equal("Justification"))
		})

		It("should not report an error if the violation is suppressed without certain rules", func() {
			sample := testutils.SampleCodeG401[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "h := md5.New()", "h := md5.New() //#nosec", 1)
			nosecPackage.AddFile("md5.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := analyzer.Report()
			Expect(issues).To(HaveLen(sample.Errors))
			Expect(issues[0].Suppressions).To(HaveLen(1))
			Expect(issues[0].Suppressions[0].Kind).To(Equal("inSource"))
			Expect(issues[0].Suppressions[0].Justification).To(Equal(""))
		})

		It("should track multiple suppressions if the violation is suppressed by both #nosec and #nosec RuleList", func() {
			sample := testutils.SampleCodeG101[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G101")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "}", "} //#nosec G101 -- Justification", 1)
			nosecSource = strings.Replace(nosecSource, "func", "//#nosec\nfunc", 1)
			nosecPackage.AddFile("pwd.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := analyzer.Report()
			Expect(issues).To(HaveLen(sample.Errors))
			Expect(issues[0].Suppressions).To(HaveLen(2))
		})

		It("should not report an error if the rule is not included", func() {
			sample := testutils.SampleCodeG101[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(true, rules.NewRuleFilter(false, "G401")).RulesInfo())

			controlPackage := testutils.NewTestPackage()
			defer controlPackage.Close()
			controlPackage.AddFile("pwd.go", source)
			err := controlPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, controlPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			controlIssues, _, _ := analyzer.Report()
			Expect(controlIssues).Should(HaveLen(sample.Errors))
			Expect(controlIssues[0].Suppressions).To(HaveLen(1))
			Expect(controlIssues[0].Suppressions[0].Kind).To(Equal("external"))
			Expect(controlIssues[0].Suppressions[0].Justification).To(Equal("Globally suppressed."))
		})

		It("should not report an error if the rule is excluded", func() {
			sample := testutils.SampleCodeG101[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(true, rules.NewRuleFilter(true, "G101")).RulesInfo())

			controlPackage := testutils.NewTestPackage()
			defer controlPackage.Close()
			controlPackage.AddFile("pwd.go", source)
			err := controlPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, controlPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := analyzer.Report()
			Expect(issues).Should(HaveLen(sample.Errors))
			Expect(issues[0].Suppressions).To(HaveLen(1))
			Expect(issues[0].Suppressions[0].Kind).To(Equal("external"))
			Expect(issues[0].Suppressions[0].Justification).To(Equal("Globally suppressed."))
		})

		It("should track multiple suppressions if the violation is multiply suppressed", func() {
			sample := testutils.SampleCodeG101[0]
			source := sample.Code[0]
			analyzer.LoadRules(rules.Generate(true, rules.NewRuleFilter(true, "G101")).RulesInfo())

			nosecPackage := testutils.NewTestPackage()
			defer nosecPackage.Close()
			nosecSource := strings.Replace(source, "}", "} //#nosec G101 -- Justification", 1)
			nosecPackage.AddFile("pwd.go", nosecSource)
			err := nosecPackage.Build()
			Expect(err).ShouldNot(HaveOccurred())
			err = analyzer.Process(buildTags, nosecPackage.Path)
			Expect(err).ShouldNot(HaveOccurred())
			issues, _, _ := analyzer.Report()
			Expect(issues).Should(HaveLen(sample.Errors))
			Expect(issues[0].Suppressions).To(HaveLen(2))
		})
	})
})
