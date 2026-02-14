package analyzers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/analysis"
)

func TestNewAnalyzerSet(t *testing.T) {
	set := NewAnalyzerSet()
	require.NotNil(t, set)
	// Analyzers can be nil initially (nil slice is valid in Go)
	assert.NotNil(t, set.AnalyzerSuppressedMap)
	assert.Equal(t, 0, len(set.Analyzers))
	assert.Equal(t, 0, len(set.AnalyzerSuppressedMap))
}

func TestAnalyzerSet_Register(t *testing.T) {
	set := NewAnalyzerSet()
	analyzer := &analysis.Analyzer{
		Name: "test-analyzer",
		Doc:  "Test analyzer",
	}

	set.Register(analyzer, false)

	assert.Equal(t, 1, len(set.Analyzers))
	assert.Equal(t, analyzer, set.Analyzers[0])
	assert.False(t, set.AnalyzerSuppressedMap["test-analyzer"])
}

func TestAnalyzerSet_RegisterSuppressed(t *testing.T) {
	set := NewAnalyzerSet()
	analyzer := &analysis.Analyzer{
		Name: "suppressed-analyzer",
		Doc:  "Suppressed analyzer",
	}

	set.Register(analyzer, true)

	assert.Equal(t, 1, len(set.Analyzers))
	assert.True(t, set.AnalyzerSuppressedMap["suppressed-analyzer"])
}

func TestAnalyzerSet_RegisterMultiple(t *testing.T) {
	set := NewAnalyzerSet()

	analyzer1 := &analysis.Analyzer{Name: "analyzer1"}
	analyzer2 := &analysis.Analyzer{Name: "analyzer2"}
	analyzer3 := &analysis.Analyzer{Name: "analyzer3"}

	set.Register(analyzer1, false)
	set.Register(analyzer2, true)
	set.Register(analyzer3, false)

	assert.Equal(t, 3, len(set.Analyzers))
	assert.False(t, set.AnalyzerSuppressedMap["analyzer1"])
	assert.True(t, set.AnalyzerSuppressedMap["analyzer2"])
	assert.False(t, set.AnalyzerSuppressedMap["analyzer3"])
}

func TestAnalyzerSet_IsSuppressed(t *testing.T) {
	set := NewAnalyzerSet()

	analyzer1 := &analysis.Analyzer{Name: "active"}
	analyzer2 := &analysis.Analyzer{Name: "suppressed"}

	set.Register(analyzer1, false)
	set.Register(analyzer2, true)

	assert.False(t, set.IsSuppressed("active"))
	assert.True(t, set.IsSuppressed("suppressed"))
}

func TestAnalyzerSet_IsSuppressed_NonExistent(t *testing.T) {
	set := NewAnalyzerSet()

	// Non-existent analyzer should return false
	assert.False(t, set.IsSuppressed("non-existent"))
}

func TestAnalyzerSet_PreservesOrder(t *testing.T) {
	set := NewAnalyzerSet()

	analyzer1 := &analysis.Analyzer{Name: "first"}
	analyzer2 := &analysis.Analyzer{Name: "second"}
	analyzer3 := &analysis.Analyzer{Name: "third"}

	set.Register(analyzer1, false)
	set.Register(analyzer2, false)
	set.Register(analyzer3, false)

	require.Equal(t, 3, len(set.Analyzers))
	assert.Equal(t, "first", set.Analyzers[0].Name)
	assert.Equal(t, "second", set.Analyzers[1].Name)
	assert.Equal(t, "third", set.Analyzers[2].Name)
}

func TestAnalyzerSet_EmptySet(t *testing.T) {
	set := NewAnalyzerSet()

	// Empty set should have no analyzers
	assert.Equal(t, 0, len(set.Analyzers))
	assert.False(t, set.IsSuppressed("anything"))
}

func TestAnalyzerSet_RegisterSameAnalyzerTwice(t *testing.T) {
	set := NewAnalyzerSet()
	analyzer := &analysis.Analyzer{Name: "duplicate"}

	set.Register(analyzer, false)
	set.Register(analyzer, true)

	// Both registrations should be recorded
	assert.Equal(t, 2, len(set.Analyzers))
	// Last registration wins for suppression status
	assert.True(t, set.AnalyzerSuppressedMap["duplicate"])
}
