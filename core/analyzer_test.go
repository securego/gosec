package core

import (
	"path/filepath"
	"testing"
)

func TestProcessSource(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)
	source := `
        package main
        import(
                "fmt"
        )
        func main() {
                fmt.Println("test process source")
        }
        `
	err := analyzer.ProcessSource("pkg", "test.go", source)
	if err != nil {
		t.Errorf("Failed to process the source: %v\n", err)
	}
}

func TestProcessPkg(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)

	file1 := filepath.Join("fixtures", "a.go")
	file2 := filepath.Join("fixtures", "b.go")

	err := analyzer.ProcessPkg("fixtures", file1, file2)
	if err != nil {
		t.Errorf("Failed to process a package composed of multiple files: %v\n", err)
	}
}
