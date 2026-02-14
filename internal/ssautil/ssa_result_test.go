package ssautil_test

import (
	"log"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"

	"github.com/securego/gosec/v2/internal/ssautil"
)

func TestSSAUtil(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SSA Utility Suite")
}

var _ = Describe("SSA Result Utilities", func() {
	Context("GetSSAResult", func() {
		It("should return error when SSA result is not present", func() {
			pass := &analysis.Pass{
				ResultOf: make(map[*analysis.Analyzer]interface{}),
			}

			result, err := ssautil.GetSSAResult(pass)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ssautil.ErrNoSSAResult))
			Expect(result).To(BeNil())
		})

		It("should return error when result is not SSAAnalyzerResult type", func() {
			pass := &analysis.Pass{
				ResultOf: map[*analysis.Analyzer]interface{}{
					buildssa.Analyzer: "invalid type",
				},
			}

			result, err := ssautil.GetSSAResult(pass)
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(ssautil.ErrInvalidSSAType))
			Expect(result).To(BeNil())
		})

		It("should successfully return SSAAnalyzerResult when present", func() {
			expectedResult := &ssautil.SSAAnalyzerResult{
				Config: map[string]any{"test": "value"},
				Logger: log.Default(),
				SSA:    nil, // nil is acceptable for this test
			}

			pass := &analysis.Pass{
				ResultOf: map[*analysis.Analyzer]interface{}{
					buildssa.Analyzer: expectedResult,
				},
			}

			result, err := ssautil.GetSSAResult(pass)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(expectedResult))
			Expect(result.Config).To(HaveKey("test"))
			Expect(result.Config["test"]).To(Equal("value"))
		})

		It("should handle nil SSA field", func() {
			expectedResult := &ssautil.SSAAnalyzerResult{
				Config: map[string]any{},
				Logger: nil,
				SSA:    nil,
			}

			pass := &analysis.Pass{
				ResultOf: map[*analysis.Analyzer]interface{}{
					buildssa.Analyzer: expectedResult,
				},
			}

			result, err := ssautil.GetSSAResult(pass)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(expectedResult))
			Expect(result.SSA).To(BeNil())
		})

		It("should handle empty config", func() {
			expectedResult := &ssautil.SSAAnalyzerResult{
				Config: make(map[string]any),
				Logger: log.Default(),
				SSA:    nil,
			}

			pass := &analysis.Pass{
				ResultOf: map[*analysis.Analyzer]interface{}{
					buildssa.Analyzer: expectedResult,
				},
			}

			result, err := ssautil.GetSSAResult(pass)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Config).NotTo(BeNil())
			Expect(result.Config).To(BeEmpty())
		})
	})

	Context("Error types", func() {
		It("should have proper error messages", func() {
			Expect(ssautil.ErrNoSSAResult.Error()).To(Equal("no SSA result found in the analysis pass"))
			Expect(ssautil.ErrInvalidSSAType.Error()).To(Equal("the analysis pass result is not of type SSA"))
		})
	})
})
