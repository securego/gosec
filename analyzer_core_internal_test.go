package gosec

import (
	"errors"
	"go/types"
	"io"
	"log"
	"testing"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/packages"

	"github.com/securego/gosec/v2/issue"
)

func TestCheckAnalyzersShortCircuitsWithoutAnalyzers(t *testing.T) {
	t.Parallel()

	a := NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
	issues, stats := a.checkAnalyzers(nil, nil)

	if issues != nil {
		t.Fatalf("expected nil issues when no analyzers are loaded")
	}
	if stats == nil {
		t.Fatalf("expected non-nil metrics")
	}
	if stats.NumFound != 0 {
		t.Fatalf("unexpected findings count: %d", stats.NumFound)
	}
}

func TestCheckAnalyzersHandlesSSABuildFailure(t *testing.T) {
	t.Parallel()

	a := NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
	a.analyzerSet.Register(&analysis.Analyzer{Name: "dummy", Run: func(*analysis.Pass) (any, error) { return nil, nil }}, false)

	pkg := &packages.Package{Name: "broken"}
	issues, stats := a.checkAnalyzers(pkg, nil)

	if len(issues) != 0 {
		t.Fatalf("expected no issues when SSA build fails")
	}
	if stats == nil || stats.NumFound != 0 {
		t.Fatalf("expected empty metrics, got %#v", stats)
	}
}

func TestCheckAnalyzersWithSSAWrapperMergesIssues(t *testing.T) {
	t.Parallel()

	a := NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
	a.analyzerSet.Register(&analysis.Analyzer{
		Name: "dummy",
		Run: func(*analysis.Pass) (any, error) {
			return []*issue.Issue{{
				RuleID:     "T999",
				File:       "dummy.go",
				Line:       "1",
				Col:        "1",
				Severity:   issue.High,
				Confidence: issue.High,
				What:       "dummy finding",
			}}, nil
		},
	}, false)

	a.CheckAnalyzersWithSSA(&packages.Package{Name: "pkg"}, &buildssa.SSA{})
	issues, stats, _ := a.Report()

	if len(issues) != 1 {
		t.Fatalf("unexpected issues count: got %d want 1", len(issues))
	}
	if stats.NumFound != 1 {
		t.Fatalf("unexpected findings count: got %d want 1", stats.NumFound)
	}
}

func TestBuildSSANilPackage(t *testing.T) {
	t.Parallel()

	a := NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
	_, err := a.buildSSA(nil)
	if err == nil {
		t.Fatalf("expected error for nil package")
	}
	if !errors.Is(err, ErrNilPackage) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSSATypeInfoValidation(t *testing.T) {
	t.Parallel()

	a := NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))

	if _, err := a.buildSSA(&packages.Package{Name: "missing-types"}); err == nil {
		t.Fatalf("expected error for missing types")
	}

	pkgMissingInfo := &packages.Package{Name: "missing-typesinfo"}
	pkgMissingInfo.Types = types.NewPackage("example.com/p", "p")
	_, err := a.buildSSA(pkgMissingInfo)
	if err == nil {
		t.Fatalf("expected error for missing types info")
	}
}
