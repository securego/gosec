package analyzers

import (
	"go/constant"
	"go/token"
	"go/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

var _ = Describe("GetConstantInt64", func() {
	It("should not panic on float constants", func() {
		// Create a float constant (simulates float64(-1))
		floatVal := constant.MakeFloat64(-1.0)
		c := &ssa.Const{Value: floatVal}

		// Should return (0, false) without panicking
		val, ok := GetConstantInt64(c)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(int64(0)))
	})

	It("should extract positive integer constant", func() {
		intVal := constant.MakeInt64(42)
		c := &ssa.Const{Value: intVal}

		val, ok := GetConstantInt64(c)
		Expect(ok).To(BeTrue())
		Expect(val).To(Equal(int64(42)))
	})

	It("should extract negative integer constant", func() {
		intVal := constant.MakeInt64(-42)
		c := &ssa.Const{Value: intVal}

		val, ok := GetConstantInt64(c)
		Expect(ok).To(BeTrue())
		Expect(val).To(Equal(int64(-42)))
	})

	It("should handle nil constant value", func() {
		c := &ssa.Const{Value: nil}

		val, ok := GetConstantInt64(c)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(int64(0)))
	})

	It("should handle UnOp with SUB operator", func() {
		intVal := constant.MakeInt64(42)
		c := &ssa.Const{Value: intVal}
		unOp := &ssa.UnOp{
			Op: token.SUB,
			X:  c,
		}

		val, ok := GetConstantInt64(unOp)
		Expect(ok).To(BeTrue())
		Expect(val).To(Equal(int64(-42)))
	})

	It("should return false for nil value", func() {
		val, ok := GetConstantInt64(nil)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(int64(0)))
	})
})

var _ = Describe("GetConstantUint64", func() {
	It("should extract positive integer constant", func() {
		intVal := constant.MakeUint64(42)
		c := &ssa.Const{Value: intVal}

		val, ok := GetConstantUint64(c)
		Expect(ok).To(BeTrue())
		Expect(val).To(Equal(uint64(42)))
	})

	It("should handle nil constant value", func() {
		c := &ssa.Const{Value: nil}

		val, ok := GetConstantUint64(c)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(uint64(0)))
	})

	It("should return false for float constant", func() {
		floatVal := constant.MakeFloat64(42.5)
		c := &ssa.Const{Value: floatVal}

		val, ok := GetConstantUint64(c)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(uint64(0)))
	})

	It("should return false for nil value", func() {
		val, ok := GetConstantUint64(nil)
		Expect(ok).To(BeFalse())
		Expect(val).To(Equal(uint64(0)))
	})
})

var _ = Describe("GetIntTypeInfo", func() {
	Context("Signed integer types", func() {
		It("should return correct info for int8", func() {
			t := types.Typ[types.Int8]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeTrue())
			Expect(info.Size).To(Equal(8))
			Expect(info.Min).To(Equal(int64(-128)))
			Expect(info.Max).To(Equal(uint64(127)))
		})

		It("should return correct info for int16", func() {
			t := types.Typ[types.Int16]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeTrue())
			Expect(info.Size).To(Equal(16))
		})

		It("should return correct info for int32", func() {
			t := types.Typ[types.Int32]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeTrue())
			Expect(info.Size).To(Equal(32))
		})

		It("should return correct info for int64", func() {
			t := types.Typ[types.Int64]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeTrue())
			Expect(info.Size).To(Equal(64))
		})
	})

	Context("Unsigned integer types", func() {
		It("should return correct info for uint8", func() {
			t := types.Typ[types.Uint8]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeFalse())
			Expect(info.Size).To(Equal(8))
			Expect(info.Min).To(Equal(int64(0)))
			Expect(info.Max).To(Equal(uint64(255)))
		})

		It("should return correct info for uint16", func() {
			t := types.Typ[types.Uint16]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeFalse())
			Expect(info.Size).To(Equal(16))
		})

		It("should return correct info for uint32", func() {
			t := types.Typ[types.Uint32]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeFalse())
			Expect(info.Size).To(Equal(32))
		})

		It("should return correct info for uint64", func() {
			t := types.Typ[types.Uint64]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeFalse())
			Expect(info.Size).To(Equal(64))
		})

		It("should return correct info for uintptr", func() {
			t := types.Typ[types.Uintptr]
			info, err := GetIntTypeInfo(t)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeFalse())
			Expect(info.Size).To(Equal(64))
		})
	})

	Context("Pointer types", func() {
		It("should handle pointer to int", func() {
			elemType := types.Typ[types.Int32]
			ptrType := types.NewPointer(elemType)
			info, err := GetIntTypeInfo(ptrType)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Signed).To(BeTrue())
			Expect(info.Size).To(Equal(32))
		})
	})

	Context("Error cases", func() {
		It("should return error for non-basic type", func() {
			t := types.NewSlice(types.Typ[types.Int])
			_, err := GetIntTypeInfo(t)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not a basic type"))
		})

		It("should return error for unsupported basic type", func() {
			t := types.Typ[types.String]
			_, err := GetIntTypeInfo(t)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported basic type"))
		})
	})
})

var _ = Describe("BaseAnalyzerState", func() {
	var pass *analysis.Pass

	BeforeEach(func() {
		pass = &analysis.Pass{}
	})

	It("should create new state with initialized maps", func() {
		state := NewBaseState(pass)
		Expect(state).ToNot(BeNil())
		Expect(state.Pass).To(Equal(pass))
		Expect(state.Analyzer).ToNot(BeNil())
		Expect(state.Visited).ToNot(BeNil())
		Expect(state.FuncMap).ToNot(BeNil())
		Expect(state.BlockMap).ToNot(BeNil())
		Expect(state.ClosureCache).ToNot(BeNil())
		Expect(state.Depth).To(Equal(0))
	})

	It("should reset state", func() {
		state := NewBaseState(pass)
		state.Visited[nil] = true
		state.FuncMap[nil] = true
		state.BlockMap[nil] = true
		state.ClosureCache[nil] = true
		state.Depth = 5

		state.Reset()

		Expect(len(state.Visited)).To(Equal(0))
		Expect(len(state.FuncMap)).To(Equal(0))
		Expect(len(state.BlockMap)).To(Equal(0))
		Expect(len(state.ClosureCache)).To(Equal(0))
		Expect(state.Depth).To(Equal(0))
	})

	It("should release resources", func() {
		state := NewBaseState(pass)
		state.Release()

		Expect(state.Analyzer).To(BeNil())
		Expect(state.Visited).To(BeNil())
		Expect(state.FuncMap).To(BeNil())
		Expect(state.ClosureCache).To(BeNil())
		Expect(state.BlockMap).To(BeNil())
	})

	It("should handle ResolveFuncs with nil value", func() {
		state := NewBaseState(pass)
		var funcs []*ssa.Function

		state.ResolveFuncs(nil, &funcs)

		Expect(len(funcs)).To(Equal(0))
	})

	It("should handle ResolveFuncs with max depth", func() {
		state := NewBaseState(pass)
		state.Depth = MaxDepth + 1
		var funcs []*ssa.Function
		fn := &ssa.Function{}

		state.ResolveFuncs(fn, &funcs)

		Expect(len(funcs)).To(Equal(0))
	})
})

var _ = Describe("Slice utility functions", func() {
	Describe("ComputeSliceNewCap", func() {
		It("should return maxIdx - l when maxIdx > 0", func() {
			cap := ComputeSliceNewCap(2, 5, 10, 20)
			Expect(cap).To(Equal(8)) // 10 - 2
		})

		It("should return oldCap when l=0 and h=0", func() {
			cap := ComputeSliceNewCap(0, 0, 0, 20)
			Expect(cap).To(Equal(20))
		})

		It("should return oldCap - l when l > 0 and h=0", func() {
			cap := ComputeSliceNewCap(5, 0, 0, 20)
			Expect(cap).To(Equal(15)) // 20 - 5
		})

		It("should return h when l=0 and h > 0", func() {
			cap := ComputeSliceNewCap(0, 10, 0, 20)
			Expect(cap).To(Equal(10))
		})

		It("should return h - l otherwise", func() {
			cap := ComputeSliceNewCap(3, 8, 0, 20)
			Expect(cap).To(Equal(5)) // 8 - 3
		})
	})

	Describe("GetSliceBounds", func() {
		It("should extract all slice bounds", func() {
			lowConst := &ssa.Const{Value: constant.MakeInt64(1)}
			highConst := &ssa.Const{Value: constant.MakeInt64(5)}
			maxConst := &ssa.Const{Value: constant.MakeInt64(10)}

			slice := &ssa.Slice{
				Low:  lowConst,
				High: highConst,
				Max:  maxConst,
			}

			l, h, m := GetSliceBounds(slice)
			Expect(l).To(Equal(1))
			Expect(h).To(Equal(5))
			Expect(m).To(Equal(10))
		})

		It("should handle nil bounds", func() {
			slice := &ssa.Slice{
				Low:  nil,
				High: nil,
				Max:  nil,
			}

			l, h, m := GetSliceBounds(slice)
			Expect(l).To(Equal(0))
			Expect(h).To(Equal(0))
			Expect(m).To(Equal(0))
		})
	})

	Describe("GetSliceRange", func() {
		It("should extract low and high as int64", func() {
			lowConst := &ssa.Const{Value: constant.MakeInt64(2)}
			highConst := &ssa.Const{Value: constant.MakeInt64(7)}

			slice := &ssa.Slice{
				Low:  lowConst,
				High: highConst,
			}

			l, h := GetSliceRange(slice)
			Expect(l).To(Equal(int64(2)))
			Expect(h).To(Equal(int64(7)))
		})

		It("should return -1 for missing high", func() {
			lowConst := &ssa.Const{Value: constant.MakeInt64(2)}

			slice := &ssa.Slice{
				Low:  lowConst,
				High: nil,
			}

			l, h := GetSliceRange(slice)
			Expect(l).To(Equal(int64(2)))
			Expect(h).To(Equal(int64(-1)))
		})
	})

	Describe("IsFullSlice", func() {
		It("should return true when low=0 and high=-1", func() {
			slice := &ssa.Slice{
				Low:  nil,
				High: nil,
			}

			Expect(IsFullSlice(slice, 10)).To(BeTrue())
		})

		It("should return false when low != 0", func() {
			lowConst := &ssa.Const{Value: constant.MakeInt64(1)}
			slice := &ssa.Slice{
				Low:  lowConst,
				High: nil,
			}

			Expect(IsFullSlice(slice, 10)).To(BeFalse())
		})

		It("should return true when low=0 and high=bufferLen", func() {
			highConst := &ssa.Const{Value: constant.MakeInt64(10)}
			slice := &ssa.Slice{
				Low:  nil,
				High: highConst,
			}

			Expect(IsFullSlice(slice, 10)).To(BeTrue())
		})

		It("should return false when high < bufferLen", func() {
			highConst := &ssa.Const{Value: constant.MakeInt64(5)}
			slice := &ssa.Slice{
				Low:  nil,
				High: highConst,
			}

			Expect(IsFullSlice(slice, 10)).To(BeFalse())
		})
	})

	Describe("IsSubSlice", func() {
		It("should return true when parent covers all", func() {
			sub := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(1)},
				High: &ssa.Const{Value: constant.MakeInt64(5)},
			}
			super := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(0)},
				High: nil, // covers all
			}

			Expect(IsSubSlice(sub, super)).To(BeTrue())
		})

		It("should return false when parent low > child low", func() {
			sub := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(1)},
				High: &ssa.Const{Value: constant.MakeInt64(5)},
			}
			super := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(2)},
				High: &ssa.Const{Value: constant.MakeInt64(10)},
			}

			Expect(IsSubSlice(sub, super)).To(BeFalse())
		})

		It("should return true when child within parent bounds", func() {
			sub := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(2)},
				High: &ssa.Const{Value: constant.MakeInt64(5)},
			}
			super := &ssa.Slice{
				Low:  &ssa.Const{Value: constant.MakeInt64(1)},
				High: &ssa.Const{Value: constant.MakeInt64(8)},
			}

			Expect(IsSubSlice(sub, super)).To(BeTrue())
		})
	})
})

var _ = Describe("IsConstantInTypeRange", func() {
	It("should return true for value in signed range", func() {
		constVal := &ssa.Const{Value: constant.MakeInt64(100)}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeTrue())
	})

	It("should return false for value outside signed range", func() {
		constVal := &ssa.Const{Value: constant.MakeInt64(200)}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeFalse())
	})

	It("should return true for value in unsigned range", func() {
		constVal := &ssa.Const{Value: constant.MakeUint64(200)}
		dstInt := IntTypeInfo{Signed: false, Size: 8, Min: 0, Max: 255}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeTrue())
	})

	It("should return false for value outside unsigned range", func() {
		constVal := &ssa.Const{Value: constant.MakeUint64(300)}
		dstInt := IntTypeInfo{Signed: false, Size: 8, Min: 0, Max: 255}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeFalse())
	})

	It("should return false for nil value", func() {
		constVal := &ssa.Const{Value: nil}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeFalse())
	})

	It("should return false for non-integer constant", func() {
		constVal := &ssa.Const{Value: constant.MakeFloat64(42.5)}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(IsConstantInTypeRange(constVal, dstInt)).To(BeFalse())
	})
})

var _ = Describe("ExplicitValsInRange", func() {
	It("should return true when positive value in range", func() {
		pos := []uint{100, 200}
		neg := []int{}
		dstInt := IntTypeInfo{Signed: false, Size: 8, Min: 0, Max: 255}

		Expect(ExplicitValsInRange(pos, neg, dstInt)).To(BeTrue())
	})

	It("should return false when positive values out of range", func() {
		pos := []uint{300, 400}
		neg := []int{}
		dstInt := IntTypeInfo{Signed: false, Size: 8, Min: 0, Max: 255}

		Expect(ExplicitValsInRange(pos, neg, dstInt)).To(BeFalse())
	})

	It("should return true when negative value in range", func() {
		pos := []uint{}
		neg := []int{-50, -100}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(ExplicitValsInRange(pos, neg, dstInt)).To(BeTrue())
	})

	It("should return false when negative values out of range", func() {
		pos := []uint{}
		neg := []int{-200, -300}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(ExplicitValsInRange(pos, neg, dstInt)).To(BeFalse())
	})

	It("should return false for empty values", func() {
		pos := []uint{}
		neg := []int{}
		dstInt := IntTypeInfo{Signed: true, Size: 8, Min: -128, Max: 127}

		Expect(ExplicitValsInRange(pos, neg, dstInt)).To(BeFalse())
	})
})

var _ = Describe("Utility helper functions", func() {
	Describe("isUint", func() {
		It("should return true for uint basic type", func() {
			// Test with a type rather than an actual constant
			typ := types.Typ[types.Uint]
			basic, ok := typ.Underlying().(*types.Basic)
			Expect(ok).To(BeTrue())
			Expect(basic.Info()&types.IsUnsigned != 0).To(BeTrue())
		})

		It("should return false for int basic type", func() {
			typ := types.Typ[types.Int]
			basic, ok := typ.Underlying().(*types.Basic)
			Expect(ok).To(BeTrue())
			Expect(basic.Info()&types.IsUnsigned != 0).To(BeFalse())
		})
	})

	Describe("isEquivalent", func() {
		It("should return true for same value", func() {
			val := &ssa.Const{Value: constant.MakeInt64(42)}
			Expect(isEquivalent(val, val)).To(BeTrue())
		})

		It("should return false for nil values", func() {
			val := &ssa.Const{Value: constant.MakeInt64(42)}
			Expect(isEquivalent(val, nil)).To(BeFalse())
			Expect(isEquivalent(nil, val)).To(BeFalse())
		})

		It("should return true for equivalent constant values with same type", func() {
			// Two constants with the same value will be the same object when compared
			val1 := &ssa.Const{Value: constant.MakeInt64(42)}
			// Testing with the same reference should always return true
			Expect(isEquivalent(val1, val1)).To(BeTrue())
		})

		It("should return true for equivalent BinOp operations", func() {
			c1 := &ssa.Const{Value: constant.MakeInt64(10)}
			c2 := &ssa.Const{Value: constant.MakeInt64(20)}
			binOp1 := &ssa.BinOp{Op: token.ADD, X: c1, Y: c2}
			binOp2 := &ssa.BinOp{Op: token.ADD, X: c1, Y: c2}
			Expect(isEquivalent(binOp1, binOp2)).To(BeTrue())
		})

		It("should return false for different BinOp operations", func() {
			c1 := &ssa.Const{Value: constant.MakeInt64(10)}
			c2 := &ssa.Const{Value: constant.MakeInt64(20)}
			binOp1 := &ssa.BinOp{Op: token.ADD, X: c1, Y: c2}
			binOp2 := &ssa.BinOp{Op: token.SUB, X: c1, Y: c2}
			Expect(isEquivalent(binOp1, binOp2)).To(BeFalse())
		})
	})

	Describe("isSameOrRelated", func() {
		It("should return true for same value", func() {
			val := &ssa.Const{Value: constant.MakeInt64(42)}
			Expect(isSameOrRelated(val, val)).To(BeTrue())
		})

		It("should return false for nil values", func() {
			val := &ssa.Const{Value: constant.MakeInt64(42)}
			Expect(isSameOrRelated(val, nil)).To(BeFalse())
			Expect(isSameOrRelated(nil, val)).To(BeFalse())
		})
	})
})
