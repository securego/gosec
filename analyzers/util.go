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
	"cmp"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"log"
	"os"
	"regexp"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

// isSliceInsideBounds checks if the requested slice range is within the parent slice's boundaries.
func isSliceInsideBounds(l, h int, cl, ch int) bool {
	return (l <= cl && h >= ch) && (l <= ch && h >= cl)
}

// isThreeIndexSliceInsideBounds validates the boundaries and capacity of a 3-index slice (s[i:j:k]).
func isThreeIndexSliceInsideBounds(l, h, maxIdx int, oldCap int) bool {
	return l >= 0 && h >= l && maxIdx >= h && maxIdx <= oldCap
}

// MaxDepth defines the maximum recursion depth for SSA analysis to avoid infinite loops and memory exhaustion.
const MaxDepth = 20

// SSAAnalyzerResult contains various information returned by the
// SSA analysis along with some configuration
type SSAAnalyzerResult struct {
	Config map[string]interface{}
	Logger *log.Logger
	SSA    *buildssa.SSA
}

// BuildDefaultAnalyzers returns the default list of analyzers
func BuildDefaultAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		newConversionOverflowAnalyzer("G115", "Type conversion which leads to integer overflow"),
		newSliceBoundsAnalyzer("G602", "Possible slice bounds out of range"),
		newHardCodedNonce("G407", "Use of hardcoded IV/nonce for encryption"),
	}
}

// getSSAResult retrieves the SSA result from analysis pass
func getSSAResult(pass *analysis.Pass) (*SSAAnalyzerResult, error) {
	result, ok := pass.ResultOf[buildssa.Analyzer]
	if !ok {
		return nil, fmt.Errorf("no SSA result found in the analysis pass")
	}
	ssaResult, ok := result.(*SSAAnalyzerResult)
	if !ok {
		return nil, fmt.Errorf("the analysis pass result is not of type SSA")
	}
	return ssaResult, nil
}

// newIssue creates a new gosec issue
func newIssue(analyzerID string, desc string, fileSet *token.FileSet,
	pos token.Pos, severity, confidence issue.Score,
) *issue.Issue {
	file := fileSet.File(pos)
	// This can occur when there is a compilation issue into the code.
	if file == nil {
		return &issue.Issue{}
	}
	line := file.Line(pos)
	col := file.Position(pos).Column

	return &issue.Issue{
		RuleID:     analyzerID,
		File:       file.Name(),
		Line:       strconv.Itoa(line),
		Col:        strconv.Itoa(col),
		Severity:   severity,
		Confidence: confidence,
		What:       desc,
		Cwe:        issue.GetCweByRule(analyzerID),
		Code:       issueCodeSnippet(fileSet, pos),
	}
}

func issueCodeSnippet(fileSet *token.FileSet, pos token.Pos) string {
	file := fileSet.File(pos)

	start := (int64)(file.Line(pos))
	if start-issue.SnippetOffset > 0 {
		start = start - issue.SnippetOffset
	}
	end := (int64)(file.Line(pos))
	end = end + issue.SnippetOffset

	var code string
	if file, err := os.Open(file.Name()); err == nil {
		defer file.Close() // #nosec
		code, err = issue.CodeSnippet(file, start, end)
		if err != nil {
			return err.Error()
		}
	}
	return code
}

// IntTypeInfo represents integer type properties
type IntTypeInfo struct {
	Signed bool
	Size   int
	Min    int
	Max    uint
}

// ParseIntType parses an integer type string into IntTypeInfo
func ParseIntType(intType string) (IntTypeInfo, error) {
	re := regexp.MustCompile(`^(?P<type>u?int)(?P<size>\d{1,2})?$`)
	matches := re.FindStringSubmatch(intType)
	if matches == nil {
		return IntTypeInfo{}, fmt.Errorf("no integer type match found for %s", intType)
	}

	it := matches[re.SubexpIndex("type")]
	is := matches[re.SubexpIndex("size")]

	signed := it == "int"
	intSize := strconv.IntSize
	if is != "" {
		var err error
		intSize, err = strconv.Atoi(is)
		if err != nil {
			return IntTypeInfo{}, fmt.Errorf("failed to parse the integer type size: %w", err)
		}
	}

	if intSize != 8 && intSize != 16 && intSize != 32 && intSize != 64 && is != "" {
		return IntTypeInfo{}, fmt.Errorf("invalid bit size: %d", intSize)
	}

	var minVal int
	var maxVal uint

	if signed {
		shiftAmount := intSize - 1
		if shiftAmount < 0 {
			return IntTypeInfo{}, fmt.Errorf("invalid shift amount: %d", shiftAmount)
		}
		maxVal = (1 << uint(shiftAmount)) - 1
		minVal = -1 << (intSize - 1)
	} else {
		maxVal = (1 << uint(intSize)) - 1
		minVal = 0
	}

	return IntTypeInfo{
		Signed: signed,
		Size:   intSize,
		Min:    minVal,
		Max:    maxVal,
	}, nil
}

// GetConstantInt64 extracts a constant int64 value from an ssa.Value
func GetConstantInt64(v ssa.Value) (int64, bool) {
	if c, ok := v.(*ssa.Const); ok {
		if c.Value != nil {
			if val, ok := constant.Int64Val(c.Value); ok {
				return val, true
			}
		}
	}
	return 0, false
}

// GetSliceBounds extracts low, high, and max indices from a slice instruction
func GetSliceBounds(s *ssa.Slice) (int, int, int) {
	var low, high, maxIdx int
	if s.Low != nil {
		if val, ok := GetConstantInt64(s.Low); ok {
			low = int(val)
		}
	}
	if s.High != nil {
		if val, ok := GetConstantInt64(s.High); ok {
			high = int(val)
		}
	}
	if s.Max != nil {
		if val, ok := GetConstantInt64(s.Max); ok {
			maxIdx = int(val)
		}
	}
	return low, high, maxIdx
}

// GetBufferLen attempts to find the constant length of a buffer/slice/array
func GetBufferLen(val ssa.Value) int64 {
	current := val
	for {
		t := current.Type()
		if ptr, ok := t.Underlying().(*types.Pointer); ok {
			t = ptr.Elem().Underlying()
		}
		if arr, ok := t.(*types.Array); ok {
			return arr.Len()
		}
		if sl, ok := current.(*ssa.Slice); ok {
			current = sl.X
			continue
		}
		break
	}
	return -1
}

// BuildCallerMap builds a map of function names to their call sites
func BuildCallerMap(funcs []*ssa.Function) map[string][]*ssa.Call {
	callerMap := make(map[string][]*ssa.Call)
	for _, f := range funcs {
		for _, b := range f.Blocks {
			for _, i := range b.Instrs {
				if c, ok := i.(*ssa.Call); ok {
					var name string
					if c.Call.Method != nil {
						name = c.Call.Method.FullName()
					} else {
						name = c.Call.Value.String()
					}
					callerMap[name] = append(callerMap[name], c)
				}
			}
		}
	}
	return callerMap
}

func minWithPtr[T cmp.Ordered](a T, b *T) T {
	if b == nil {
		return a
	}
	return min(a, *b)
}

func maxWithPtr[T cmp.Ordered](a T, b *T) T {
	if b == nil {
		return a
	}
	return max(a, *b)
}

func toPtr[T any](a T) *T {
	return &a
}
