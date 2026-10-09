// (c) Copyright gosec's authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// TestExtractBinOpBound_NilGuards tests nil safety in extractBinOpBound
func TestExtractBinOpBound_NilGuards(t *testing.T) {
	// Test nil binop
	bound, value, err := extractBinOpBound(nil)
	if err == nil {
		t.Error("expected error for nil binop")
	}
	if bound != lowerUnbounded {
		t.Errorf("expected lowerUnbounded, got %v", bound)
	}
	if value != 0 {
		t.Errorf("expected value 0, got %d", value)
	}
}

// TestExtractLenBound_NilGuards tests nil safety in extractLenBound
func TestExtractLenBound_NilGuards(t *testing.T) {
	// Test nil binop
	val, offset, ok := extractLenBound(nil)
	if ok {
		t.Error("expected false for nil binop")
	}
	if val != nil {
		t.Errorf("expected nil value, got %v", val)
	}
	if offset != 0 {
		t.Errorf("expected offset 0, got %d", offset)
	}
}

// TestSliceBoundsNilSafety tests that the analyzer doesn't crash on nil values
func TestSliceBoundsNilSafety(t *testing.T) {
	t.Run("extractBinOpBound with nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractBinOpBound panicked on nil input: %v", r)
			}
		}()
		_, _, _ = extractBinOpBound(nil)
	})

	t.Run("extractLenBound with nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractLenBound panicked on nil input: %v", r)
			}
		}()
		_, _, _ = extractLenBound(nil)
	})

	t.Run("extractBinOpBound with binop having nil X and Y", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractBinOpBound panicked on binop with nil X/Y: %v", r)
			}
		}()
		binop := &ssa.BinOp{Op: token.LSS}
		// X and Y are nil by default
		_, _, _ = extractBinOpBound(binop)
	})
}

// TestInvBound tests the invBound function
func TestInvBound(t *testing.T) {
	tests := []struct {
		name     string
		input    bound
		expected bound
	}{
		{"lowerUnbounded", lowerUnbounded, upperUnbounded},
		{"upperUnbounded", upperUnbounded, lowerUnbounded},
		{"upperBounded", upperBounded, unbounded},
		{"unbounded", unbounded, upperBounded},
		{"bounded", bounded, bounded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := invBound(tt.input)
			if result != tt.expected {
				t.Errorf("invBound(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestReverseComparison(t *testing.T) {
	tests := []struct {
		name string
		in   token.Token
		want token.Token
	}{
		{"less", token.LSS, token.GTR},
		{"less-or-equal", token.LEQ, token.GEQ},
		{"greater", token.GTR, token.LSS},
		{"greater-or-equal", token.GEQ, token.LEQ},
		{"unchanged", token.EQL, token.EQL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseComparison(tt.in); got != tt.want {
				t.Fatalf("reverseComparison(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestInvertComparison(t *testing.T) {
	tests := []struct {
		name string
		in   token.Token
		want token.Token
	}{
		{"less", token.LSS, token.GEQ},
		{"less-or-equal", token.LEQ, token.GTR},
		{"greater", token.GTR, token.LEQ},
		{"greater-or-equal", token.GEQ, token.LSS},
		{"equal", token.EQL, token.NEQ},
		{"not-equal", token.NEQ, token.EQL},
		{"unchanged", token.ILLEGAL, token.ILLEGAL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := invertComparison(tt.in); got != tt.want {
				t.Fatalf("invertComparison(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLenConditionSliceInvalidInputs(t *testing.T) {
	if got := lenConditionSlice(nil); got != nil {
		t.Fatalf("lenConditionSlice(nil) = %v, want nil", got)
	}

	binop := &ssa.BinOp{Op: token.LSS}
	if got := lenConditionSlice(binop); got != nil {
		t.Fatalf("lenConditionSlice(non-len binop) = %v, want nil", got)
	}
}

func TestMinimumLenForBranchInvalidInputs(t *testing.T) {
	if _, ok := minimumLenForBranch(nil, 0); ok {
		t.Fatal("minimumLenForBranch(nil, 0) unexpectedly succeeded")
	}

	if _, ok := minimumLenForBranch(&ssa.BinOp{}, 2); ok {
		t.Fatal("minimumLenForBranch accepted an invalid successor")
	}

	if _, ok := minimumLenForBranch(&ssa.BinOp{Op: token.LSS}, 0); ok {
		t.Fatal("minimumLenForBranch accepted a comparison without a constant")
	}
}

func TestAppendGrowthInvalidInputs(t *testing.T) {
	if _, ok := appendGrowth(nil); ok {
		t.Fatal("appendGrowth(nil) unexpectedly succeeded")
	}
	call := &ssa.Call{}
	if _, ok := appendGrowth(call); ok {
		t.Fatal("appendGrowth on empty call unexpectedly succeeded")
	}
}

func TestStaticAppendCallLenInvalidInputs(t *testing.T) {
	if _, ok := staticAppendCallLen(nil); ok {
		t.Fatal("staticAppendCallLen(nil) unexpectedly succeeded")
	}
	call := &ssa.Call{}
	if _, ok := staticAppendCallLen(call); ok {
		t.Fatal("staticAppendCallLen on empty call unexpectedly succeeded")
	}
}

func TestStaticSliceLenNil(t *testing.T) {
	if _, ok := staticSliceLen(nil); ok {
		t.Fatal("staticSliceLen(nil) unexpectedly succeeded")
	}
}

func TestCollectSliceLenGuardsNil(t *testing.T) {
	ifs := make(map[ssa.If]*ssa.BinOp)
	collectSliceLenGuards(nil, ifs)
	if len(ifs) != 0 {
		t.Fatal("collectSliceLenGuards(nil) unexpectedly added guards")
	}
}

func buildTestSSA(t *testing.T, src string) *ssa.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	pkg, err := conf.Check("p", fset, []*ast.File{f}, info)
	if err != nil {
		t.Fatalf("types.Check: %v", err)
	}
	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	ssapkg := prog.CreatePackage(pkg, []*ast.File{f}, info, true)
	ssapkg.Build()
	return ssapkg
}

func findAppendCall(fn *ssa.Function) *ssa.Call {
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if b, ok := call.Call.Value.(*ssa.Builtin); ok && b.Name() == "append" {
					return call
				}
			}
		}
	}
	return nil
}

func TestStaticAppendCallLenSSA(t *testing.T) {
	src := `package p

func appendNil() []int {
	var s []int
	return append(s, 10)
}

func appendLiteral() []int {
	s := []int{1, 2}
	return append(s, 3)
}

func appendMake() []int {
	s := make([]int, 0, 4)
	return append(s, 10)
}

func appendMulti() []int {
	var s []int
	return append(s, 10, 20, 30)
}

func appendZero() []int {
	s := []int{1}
	return append(s)
}

func appendParam(other []int) []int {
	s := []int{}
	return append(s, other...)
}
`
	ssapkg := buildTestSSA(t, src)

	tests := []struct {
		funcName string
		wantLen  int
		wantOk   bool
	}{
		{"appendNil", 1, true},
		{"appendLiteral", 3, true},
		{"appendMake", 1, true},
		{"appendMulti", 3, true},
		{"appendZero", 1, true},
		{"appendParam", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.funcName, func(t *testing.T) {
			fn := ssapkg.Func(tt.funcName)
			if fn == nil {
				t.Fatalf("function %s not found", tt.funcName)
			}
			call := findAppendCall(fn)
			if call == nil {
				t.Fatalf("append call not found in %s", tt.funcName)
			}
			gotLen, gotOk := staticAppendCallLen(call)
			if gotOk != tt.wantOk {
				t.Fatalf("staticAppendCallLen(%s) ok = %v, want %v", tt.funcName, gotOk, tt.wantOk)
			}
			if gotLen != tt.wantLen {
				t.Fatalf("staticAppendCallLen(%s) len = %d, want %d", tt.funcName, gotLen, tt.wantLen)
			}
		})
	}
}

