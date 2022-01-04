package gosec_test

import (
	"flag"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2/cmd/vflag"
)

var _ = Describe("Cli", func() {
	Context("vflag test", func() {
		It("value must be empty as parameter value contains invalid character", func() {
			os.Args = []string{"gosec", "-test1=-incorrect"}
			f := vflag.ValidatedFlag{}
			flag.Var(&f, "test1", "")
			flag.CommandLine.Init("test1", flag.ContinueOnError)
			flag.Parse()
			Expect(flag.Parsed()).Should(Equal(true))
			Expect(f.Value).Should(Equal(``))
		})
		It("value must be empty as parameter value contains invalid character without equal sign", func() {
			os.Args = []string{"gosec", "-test2= -incorrect"}
			f := vflag.ValidatedFlag{}
			flag.Var(&f, "test2", "")
			flag.CommandLine.Init("test2", flag.ContinueOnError)
			flag.Parse()
			Expect(flag.Parsed()).Should(Equal(true))
			Expect(f.Value).Should(Equal(``))
		})
		It("value must not be empty as parameter value contains valid character", func() {
			os.Args = []string{"gosec", "-test3=correct"}
			f := vflag.ValidatedFlag{}
			flag.Var(&f, "test3", "")
			flag.CommandLine.Init("test3", flag.ContinueOnError)
			flag.Parse()
			Expect(flag.Parsed()).Should(Equal(true))
			Expect(f.Value).Should(Equal(`correct`))
		})
	})
})
