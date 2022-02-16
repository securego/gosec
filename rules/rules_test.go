package rules_test

import (
	"fmt"
	"log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
	"github.com/securego/gosec/v2/testutils"
)

var _ = Describe("gosec rules", func() {
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
		runner = func(rule string, samples []testutils.CodeSample) {
			for n, sample := range samples {
				analyzer.Reset()
				analyzer.SetConfig(sample.Config)
				analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, rule)).RulesInfo())
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
		It("should detect hardcoded credentials", func() {
			runner("G101", testutils.SampleCodeG101)
		})

		It("should detect binding to all network interfaces", func() {
			runner("G102", testutils.SampleCodeG102)
		})

		It("should use of unsafe block", func() {
			runner("G103", testutils.SampleCodeG103)
		})

		It("should detect errors not being checked", func() {
			runner("G104", testutils.SampleCodeG104)
		})

		It("should detect errors not being checked in audit mode", func() {
			runner("G104", testutils.SampleCodeG104Audit)
		})

		It("should detect of ssh.InsecureIgnoreHostKey function", func() {
			runner("G106", testutils.SampleCodeG106)
		})

		It("should detect ssrf via http requests with variable url", func() {
			runner("G107", testutils.SampleCodeG107)
		})

		It("should detect pprof endpoint", func() {
			runner("G108", testutils.SampleCodeG108)
		})

		It("should detect integer overflow", func() {
			runner("G109", testutils.SampleCodeG109)
		})

		It("should detect DoS vulnerability via decompression bomb", func() {
			runner("G110", testutils.SampleCodeG110)
		})

		It("should detect sql injection via format strings", func() {
			runner("G201", testutils.SampleCodeG201)
		})

		It("should detect sql injection via string concatenation", func() {
			runner("G202", testutils.SampleCodeG202)
		})

		It("should detect unescaped html in templates", func() {
			runner("G203", testutils.SampleCodeG203)
		})

		It("should detect command execution", func() {
			runner("G204", testutils.SampleCodeG204)
		})

		It("should detect poor file permissions on mkdir", func() {
			runner("G301", testutils.SampleCodeG301)
		})

		It("should detect poor permissions when creating or chmod a file", func() {
			runner("G302", testutils.SampleCodeG302)
		})

		It("should detect insecure temp file creation", func() {
			runner("G303", testutils.SampleCodeG303)
		})

		It("should detect file path provided as taint input", func() {
			runner("G304", testutils.SampleCodeG304)
		})

		It("should detect file path traversal when extracting zip archive", func() {
			runner("G305", testutils.SampleCodeG305)
		})

		It("should detect poor permissions when writing to a file", func() {
			runner("G306", testutils.SampleCodeG306)
		})

		It("should detect unsafe defer of os.Close", func() {
			runner("G307", testutils.SampleCodeG307)
		})

		It("should detect weak crypto algorithms", func() {
			runner("G401", testutils.SampleCodeG401)
		})

		It("should detect weak crypto algorithms", func() {
			runner("G401", testutils.SampleCodeG401b)
		})

		It("should find insecure tls settings", func() {
			runner("G402", testutils.SampleCodeG402)
		})

		It("should detect weak creation of weak rsa keys", func() {
			runner("G403", testutils.SampleCodeG403)
		})

		It("should find non cryptographically secure random number sources", func() {
			runner("G404", testutils.SampleCodeG404)
		})

		It("should detect blocklisted imports - MD5", func() {
			runner("G501", testutils.SampleCodeG501)
		})

		It("should detect blocklisted imports - DES", func() {
			runner("G502", testutils.SampleCodeG502)
		})

		It("should detect blocklisted imports - RC4", func() {
			runner("G503", testutils.SampleCodeG503)
		})

		It("should detect blocklisted imports - CGI (httpoxy)", func() {
			runner("G504", testutils.SampleCodeG504)
		})

		It("should detect blocklisted imports - SHA1", func() {
			runner("G505", testutils.SampleCodeG505)
		})

		It("should detect implicit aliasing in ForRange", func() {
			runner("G601", testutils.SampleCodeG601)
		})
	})
})
