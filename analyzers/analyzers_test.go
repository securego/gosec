package analyzers_test

import (
	"fmt"
	"log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/analyzers"
	"github.com/securego/gosec/v2/testutils"
)

var _ = Describe("gosec analyzers", func() {
	var (
		logger    *log.Logger
		config    gosec.Config
		analyzer  *gosec.Analyzer
		runner    func(string, []testutils.CodeSample)
		buildTags []string
		tests     bool
	)

	BeforeEach(func() {
		logger, _ = testutils.NewLogger()
		config = gosec.NewConfig()
		analyzer = gosec.NewAnalyzer(config, tests, false, false, 1, logger)
		runner = func(analyzerId string, samples []testutils.CodeSample) {
			for n, sample := range samples {
				analyzer.Reset()
				analyzer.SetConfig(sample.Config)
				analyzer.LoadAnalyzers(analyzers.Generate(false, analyzers.NewAnalyzerFilter(false, analyzerId)).AnalyzersInfo())
				pkg := testutils.NewTestPackage()
				defer pkg.Close()
				for i, code := range sample.Code {
					pkg.AddFile(fmt.Sprintf("sample_%d_%d.go", n, i), code)
				}
				err := pkg.Build()
				Expect(err).ShouldNot(HaveOccurred())
				Expect(pkg.PrintErrors()).Should(BeZero())
				err = analyzer.Process(buildTags, pkg.Path)
				Expect(err).ShouldNot(HaveOccurred())
				issues, _, _ := analyzer.Report()
				if len(issues) != sample.Errors {
					fmt.Println(sample.Code)
				}
				Expect(issues).Should(HaveLen(sample.Errors))
			}
		}
	})

	Context("report correct errors for all samples", func() {
		It("should detect integer conversion overflow", func() {
			runner("G115", testutils.SampleCodeG115)
		})

		It("should detect hardcoded nonce/IV", func() {
			runner("G407", testutils.SampleCodeG407)
		})

		It("should detect out of bounds slice access", func() {
			runner("G602", testutils.SampleCodeG602)
		})
	})
})
