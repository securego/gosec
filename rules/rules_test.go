package rules_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/GoASTScanner/gas"

	"github.com/GoASTScanner/gas/rules"
	"github.com/GoASTScanner/gas/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("gas rules", func() {

	var (
		logger   *log.Logger
		output   *bytes.Buffer
		config   gas.Config
		analyzer *gas.Analyzer
		runner   func(string, []testutils.CodeSample)
	)

	BeforeEach(func() {
		logger, output = testutils.NewLogger()
		config = gas.NewConfig()
		analyzer = gas.NewAnalyzer(config, logger)
		runner = func(rule string, samples []testutils.CodeSample) {
			analyzer.LoadRules(rules.Generate(rules.NewRuleFilter(false, rule)).Builders()...)
			for n, sample := range samples {
				analyzer.Reset()
				pkg := testutils.NewTestPackage()
				pkg.AddFile(fmt.Sprintf("sample_%d.go", n), sample.Code)
				pkg.Build()
				e := analyzer.Process(pkg.Path)
				Expect(e).ShouldNot(HaveOccurred())
				issues, _ := analyzer.Report()
				if len(issues) != sample.Errors {
					fmt.Println(sample.Code)
				}
				Expect(issues).Should(HaveLen(sample.Errors))
			}
		}
	})

	Context("report correct errors for all samples", func() {
		It("should work for G101 samples", func() {
			runner("G101", testutils.SampleCodeG101)
		})

		It("should work for G102 samples", func() {
			runner("G102", testutils.SampleCodeG102)
		})

		It("should work for G103 samples", func() {
			runner("G103", testutils.SampleCodeG103)
		})

		It("should work for G104 samples", func() {
			runner("G104", testutils.SampleCodeG104)
		})

	})

})
