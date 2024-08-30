package analyzers

import (
	"math"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseIntType", func() {
	Context("with valid input", func() {
		DescribeTable("should correctly parse and calculate bounds for",
			func(intType string, expectedSigned bool, expectedSize int, expectedMin int, expectedMax uint) {
				result, err := parseIntType(intType)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.signed).To(Equal(expectedSigned))
				Expect(result.size).To(Equal(expectedSize))
				Expect(result.min).To(Equal(expectedMin))
				Expect(result.max).To(Equal(expectedMax))
			},
			Entry("uint8", "uint8", false, 8, 0, uint(math.MaxUint8)),
			Entry("int8", "int8", true, 8, math.MinInt8, uint(math.MaxInt8)),
			Entry("uint16", "uint16", false, 16, 0, uint(math.MaxUint16)),
			Entry("int16", "int16", true, 16, math.MinInt16, uint(math.MaxInt16)),
			Entry("uint32", "uint32", false, 32, 0, uint(math.MaxUint32)),
			Entry("int32", "int32", true, 32, math.MinInt32, uint(math.MaxInt32)),
			Entry("uint64", "uint64", false, 64, 0, uint(math.MaxUint64)),
			Entry("int64", "int64", true, 64, math.MinInt64, uint(math.MaxInt64)),
		)

		It("should use system's int size for 'int' and 'uint'", func() {
			intResult, err := parseIntType("int")
			Expect(err).NotTo(HaveOccurred())
			Expect(intResult.size).To(Equal(strconv.IntSize))

			uintResult, err := parseIntType("uint")
			Expect(err).NotTo(HaveOccurred())
			Expect(uintResult.size).To(Equal(strconv.IntSize))
		})
	})

	Context("with invalid input", func() {
		DescribeTable("should return an error for",
			func(intType string, expectedErrorString string) {
				_, err := parseIntType(intType)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedErrorString))
			},
			Entry("empty string", "", "no integer type match found for "),
			Entry("invalid type", "float64", "no integer type match found for float64"),
			Entry("invalid size", "int65", "invalid bit size: 65"),
			Entry("negative size", "int-8", "no integer type match found for int-8"),
			Entry("non-numeric size", "intABC", "no integer type match found for intABC"),
		)
	})
})

var _ = Describe("IsIntOverflow", func() {
	DescribeTable("should correctly identify overflow scenarios on a 64-bit system",
		func(src string, dst string, expectedOverflow bool) {
			result := isIntOverflow(src, dst)
			Expect(result).To(Equal(expectedOverflow))
		},
		// Unsigned to Signed conversions
		Entry("uint8 to int8", "uint8", "int8", true),
		Entry("uint8 to int16", "uint8", "int16", false),
		Entry("uint8 to int32", "uint8", "int32", false),
		Entry("uint8 to int64", "uint8", "int64", false),
		Entry("uint16 to int8", "uint16", "int8", true),
		Entry("uint16 to int16", "uint16", "int16", true),
		Entry("uint16 to int32", "uint16", "int32", false),
		Entry("uint16 to int64", "uint16", "int64", false),
		Entry("uint32 to int8", "uint32", "int8", true),
		Entry("uint32 to int16", "uint32", "int16", true),
		Entry("uint32 to int32", "uint32", "int32", true),
		Entry("uint32 to int64", "uint32", "int64", false),
		Entry("uint64 to int8", "uint64", "int8", true),
		Entry("uint64 to int16", "uint64", "int16", true),
		Entry("uint64 to int32", "uint64", "int32", true),
		Entry("uint64 to int64", "uint64", "int64", true),

		// Unsigned to Unsigned conversions
		Entry("uint8 to uint16", "uint8", "uint16", false),
		Entry("uint8 to uint32", "uint8", "uint32", false),
		Entry("uint8 to uint64", "uint8", "uint64", false),
		Entry("uint16 to uint8", "uint16", "uint8", true),
		Entry("uint16 to uint32", "uint16", "uint32", false),
		Entry("uint16 to uint64", "uint16", "uint64", false),
		Entry("uint32 to uint8", "uint32", "uint8", true),
		Entry("uint32 to uint16", "uint32", "uint16", true),
		Entry("uint32 to uint64", "uint32", "uint64", false),
		Entry("uint64 to uint8", "uint64", "uint8", true),
		Entry("uint64 to uint16", "uint64", "uint16", true),
		Entry("uint64 to uint32", "uint64", "uint32", true),

		// Signed to Unsigned conversions
		Entry("int8 to uint8", "int8", "uint8", true),
		Entry("int8 to uint16", "int8", "uint16", true),
		Entry("int8 to uint32", "int8", "uint32", true),
		Entry("int8 to uint64", "int8", "uint64", true),
		Entry("int16 to uint8", "int16", "uint8", true),
		Entry("int16 to uint16", "int16", "uint16", true),
		Entry("int16 to uint32", "int16", "uint32", true),
		Entry("int16 to uint64", "int16", "uint64", true),
		Entry("int32 to uint8", "int32", "uint8", true),
		Entry("int32 to uint16", "int32", "uint16", true),
		Entry("int32 to uint32", "int32", "uint32", true),
		Entry("int32 to uint64", "int32", "uint64", true),
		Entry("int64 to uint8", "int64", "uint8", true),
		Entry("int64 to uint16", "int64", "uint16", true),
		Entry("int64 to uint32", "int64", "uint32", true),
		Entry("int64 to uint64", "int64", "uint64", true),

		// Signed to Signed conversions
		Entry("int8 to int16", "int8", "int16", false),
		Entry("int8 to int32", "int8", "int32", false),
		Entry("int8 to int64", "int8", "int64", false),
		Entry("int16 to int8", "int16", "int8", true),
		Entry("int16 to int32", "int16", "int32", false),
		Entry("int16 to int64", "int16", "int64", false),
		Entry("int32 to int8", "int32", "int8", true),
		Entry("int32 to int16", "int32", "int16", true),
		Entry("int32 to int64", "int32", "int64", false),
		Entry("int64 to int8", "int64", "int8", true),
		Entry("int64 to int16", "int64", "int16", true),
		Entry("int64 to int32", "int64", "int32", true),

		// Same type conversions (should never overflow)
		Entry("uint8 to uint8", "uint8", "uint8", false),
		Entry("uint16 to uint16", "uint16", "uint16", false),
		Entry("uint32 to uint32", "uint32", "uint32", false),
		Entry("uint64 to uint64", "uint64", "uint64", false),
		Entry("int8 to int8", "int8", "int8", false),
		Entry("int16 to int16", "int16", "int16", false),
		Entry("int32 to int32", "int32", "int32", false),
		Entry("int64 to int64", "int64", "int64", false),
	)
})
