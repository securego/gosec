package taint

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// AnalyzerResult contains findings from a taint analysis pass.
type AnalyzerResult struct {
	Findings []Finding
}

// Finding represents a security finding from taint analysis.
type Finding struct {
	RuleID      string
	Description string
	Severity    string
	CWE         string
	Filename    string
	Line        int
	Column      int
	Code        string
	Path        []string // function call path
}

// RuleInfo holds metadata about a taint analysis rule.
type RuleInfo struct {
	ID          string
	Description string
	Severity    string
	CWE         string
}

// Predefined rules for gosec integration.
var (
	SQLInjectionRule = RuleInfo{
		ID:          "G701",
		Description: "SQL injection via string concatenation",
		Severity:    "HIGH",
		CWE:         "CWE-89",
	}

	CommandInjectionRule = RuleInfo{
		ID:          "G702",
		Description: "Command injection via user input",
		Severity:    "CRITICAL",
		CWE:         "CWE-78",
	}

	PathTraversalRule = RuleInfo{
		ID:          "G703",
		Description: "Path traversal via user input",
		Severity:    "HIGH",
		CWE:         "CWE-22",
	}

	SSRFRule = RuleInfo{
		ID:          "G704",
		Description: "SSRF via user-controlled URL",
		Severity:    "HIGH",
		CWE:         "CWE-918",
	}

	XSSRule = RuleInfo{
		ID:          "G705",
		Description: "XSS via unescaped user input",
		Severity:    "MEDIUM",
		CWE:         "CWE-79",
	}

	LogInjectionRule = RuleInfo{
		ID:          "G706",
		Description: "Log injection via user input",
		Severity:    "LOW",
		CWE:         "CWE-117",
	}
)

// NewGosecAnalyzer creates a golang.org/x/tools/go/analysis.Analyzer
// compatible with gosec's analyzer framework.
func NewGosecAnalyzer(rule RuleInfo, config Config) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     rule.ID,
		Doc:      rule.Description,
		Run:      makeAnalyzerRunner(rule, config),
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

// makeAnalyzerRunner creates the run function for an analyzer.
func makeAnalyzerRunner(rule RuleInfo, config Config) func(*analysis.Pass) (interface{}, error) {
	return func(pass *analysis.Pass) (interface{}, error) {
		// Get SSA result from buildssa analyzer
		ssaInfo, ok := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
		if !ok {
			return &AnalyzerResult{}, nil
		}

		// Collect source functions
		var srcFuncs []*ssa.Function
		for _, fn := range ssaInfo.SrcFuncs {
			if fn != nil {
				srcFuncs = append(srcFuncs, fn)
			}
		}

		if len(srcFuncs) == 0 {
			return &AnalyzerResult{}, nil
		}

		// Run taint analysis
		analyzer := New(&config)
		results := analyzer.Analyze(srcFuncs[0].Prog, srcFuncs)

		// Convert results to findings
		var findings []Finding
		for _, result := range results {
			pos := pass.Fset.Position(result.SinkPos)

			// Build path description
			var pathStrs []string
			for _, fn := range result.Path {
				pathStrs = append(pathStrs, fn.Name())
			}

			finding := Finding{
				RuleID:      rule.ID,
				Description: rule.Description,
				Severity:    rule.Severity,
				CWE:         rule.CWE,
				Filename:    pos.Filename,
				Line:        pos.Line,
				Column:      pos.Column,
				Path:        pathStrs,
			}

			findings = append(findings, finding)

			// Report to analysis pass (for use with go vet style tools)
			pass.Reportf(result.SinkPos, "%s: %s", rule.ID, rule.Description)
		}

		return &AnalyzerResult{Findings: findings}, nil
	}
}

// DefaultAnalyzers returns all predefined taint analyzers.
func DefaultAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		NewGosecAnalyzer(SQLInjectionRule, SQLInjection()),
		NewGosecAnalyzer(CommandInjectionRule, CommandInjection()),
		NewGosecAnalyzer(PathTraversalRule, PathTraversal()),
		NewGosecAnalyzer(SSRFRule, SSRF()),
		NewGosecAnalyzer(XSSRule, XSS()),
		NewGosecAnalyzer(LogInjectionRule, LogInjection()),
	}
}

// String returns a human-readable representation of a finding.
func (f Finding) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] %s\n", f.RuleID, f.Description))
	sb.WriteString(fmt.Sprintf("  Severity: %s, CWE: %s\n", f.Severity, f.CWE))
	sb.WriteString(fmt.Sprintf("  Location: %s:%d:%d\n", f.Filename, f.Line, f.Column))
	if len(f.Path) > 0 {
		sb.WriteString(fmt.Sprintf("  Call path: %s\n", strings.Join(f.Path, " -> ")))
	}
	return sb.String()
}
