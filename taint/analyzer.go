package taint

import (
	"fmt"
	"go/token"
	"os"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/internal/ssautil"
	"github.com/securego/gosec/v2/issue"
)

// RuleInfo holds metadata about a taint analysis rule.
type RuleInfo struct {
	ID          string
	Description string
	Severity    string
	CWE         string
}

// issueText builds the message for a taint finding, naming the sink so that
// two findings of one rule at different sinks do not share a message. The
// description alone is byte-identical for every finding a rule produces.
//
// The source is not named: Analyze never populates Result.Source, so
// formatSourceKey would render a zero value here.
func issueText(description string, sink Sink) string {
	return fmt.Sprintf("%s: %s", description, formatSinkKey(sink))
}

// sinkID is the comparable identity of a sink, for use as a map key. Sink
// itself holds a []int and so cannot be one.
type sinkID struct {
	pkg, receiver, method string
	pointer               bool
}

func newSinkID(sink Sink) sinkID {
	return sinkID{pkg: sink.Package, receiver: sink.Receiver, method: sink.Method, pointer: sink.Pointer}
}

// NewGosecAnalyzer creates a golang.org/x/tools/go/analysis.Analyzer
// compatible with gosec's analyzer framework.
func NewGosecAnalyzer(rule *RuleInfo, config *Config) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     rule.ID,
		Doc:      rule.Description,
		Run:      makeAnalyzerRunner(rule, config),
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

// makeAnalyzerRunner creates the run function for an analyzer.
func makeAnalyzerRunner(rule *RuleInfo, config *Config) func(*analysis.Pass) (interface{}, error) {
	return func(pass *analysis.Pass) (interface{}, error) {
		// Get SSA result using shared helper (same as G602, G115, G407)
		ssaResult, err := ssautil.GetSSAResult(pass)
		if err != nil {
			return nil, fmt.Errorf("taint analysis %s: failed to get SSA result: %w", rule.ID, err)
		}

		// Collect source functions (filter out nil)
		var srcFuncs []*ssa.Function
		for _, fn := range ssaResult.SSA.SrcFuncs {
			if fn != nil {
				srcFuncs = append(srcFuncs, fn)
			}
		}

		if len(srcFuncs) == 0 {
			return nil, nil // No functions to analyze - this is OK
		}

		// Run taint analysis
		analyzer := New(config)
		if ssaResult.Shared != nil {
			analyzer.SetCallGraph(ssaResult.Shared.CallGraph())
		}
		results := analyzer.Analyze(srcFuncs[0].Prog, srcFuncs)

		// Convert results to gosec issues
		var issues []*issue.Issue
		// One message per distinct sink rather than per finding: a rule reports
		// at a handful of sinks and can produce thousands of findings, and this
		// path is gated for allocations.
		texts := make(map[sinkID]string)
		for _, result := range results {
			// Map severity string to issue.Score
			var severity issue.Score
			switch rule.Severity {
			case "LOW":
				severity = issue.Low
			case "MEDIUM":
				severity = issue.Medium
			case "HIGH":
				severity = issue.High
			case "CRITICAL":
				severity = issue.High // gosec uses High for critical
			default:
				severity = issue.Medium
			}

			id := newSinkID(result.Sink)
			what, cached := texts[id]
			if !cached {
				what = issueText(rule.Description, result.Sink)
				texts[id] = what
			}

			// Create gosec issue using the standard helper
			newIssue := newIssue(
				rule.ID,
				what,
				pass.Fset,
				result.SinkPos,
				severity,
				issue.High, // confidence
			)

			issues = append(issues, newIssue)

			// Report to analysis pass (for use with go vet style tools)
			pass.Reportf(result.SinkPos, "%s: %s", rule.ID, what)
		}

		if len(issues) > 0 {
			return issues, nil
		}
		return nil, nil
	}
}

// newIssue creates a new gosec issue
func newIssue(analyzerID string, desc string, fileSet *token.FileSet,
	pos token.Pos, severity, confidence issue.Score,
) *issue.Issue {
	file := fileSet.File(pos)
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
	start := int64(file.Line(pos))
	if start-issue.SnippetOffset > 0 {
		start = start - issue.SnippetOffset
	}
	end := int64(file.Line(pos))
	end = end + issue.SnippetOffset

	var code string
	if f, err := os.Open(file.Name()); err == nil {
		defer f.Close() // #nosec
		code, err = issue.CodeSnippet(f, start, end)
		if err != nil {
			return err.Error()
		}
	}
	return code
}
