package sarif_test

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/report/sarif"
)

var _ = Describe("Sarif Formatter", func() {
	BeforeEach(func() {
	})
	Context("when converting to Sarif issues", func() {
		It("sarif formatted report should contain the result", func() {
			buf := new(bytes.Buffer)
			reportInfo := gosec.NewReportInfo([]*gosec.Issue{}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			err := sarif.WriteReport(buf, reportInfo, []string{})
			result := buf.String()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(ContainSubstring("\"results\": ["))
		})
	})
})
