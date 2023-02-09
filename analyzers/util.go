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
	"fmt"
	"go/token"
	"log"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// SSAAnalyzerResult contains various information returned by the
// SSA analysis along with some configuraion
type SSAAnalyzerResult struct {
	Config map[string]interface{}
	Logger *log.Logger
	SSA    *buildssa.SSA
}

// Score type used by severity and confidence values
// TODO: remove this duplicated type
type Score int

const (
	// Low severity or confidence
	Low Score = iota
	// Medium severity or confidence
	Medium
	// High severity or confidence
	High
)

// Issue is returned by a gosec rule if it discovers an issue with the scanned code.
// TODO: remove this duplicated type
type Issue struct {
	Severity   Score  `json:"severity"`    // issue severity (how problematic it is)
	Confidence Score  `json:"confidence"`  // issue confidence (how sure we are we found it)
	AnalyzerID string `json:"analyzer_id"` // Human readable explanation
	What       string `json:"details"`     // Human readable explanation
	File       string `json:"file"`        // File name we found it in
	Code       string `json:"code"`        // Impacted code line
	Line       string `json:"line"`        // Line number in file
	Col        string `json:"column"`      // Column number in line
}

// BuildDefaultAnalyzers returns the default list of analyzers
func BuildDefaultAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		newSSRFAnalyzer("G107", "URL provided to HTTP request as taint input"),
	}
}

// getSSAResult retrives the SSA result from analysis pass
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

func newIssue(analyzerID string, desc string, fileSet *token.FileSet, pos token.Pos, severity Score, confidence Score) *Issue {
	file := fileSet.File(pos)
	line := file.Line(pos)
	col := file.Position(pos).Column
	// TODO: extract the code snippet and map the CWE
	return &Issue{
		File:       file.Name(),
		Line:       strconv.Itoa(line),
		Col:        strconv.Itoa(col),
		Severity:   severity,
		Confidence: confidence,
		AnalyzerID: analyzerID,
		What:       desc,
	}
}
