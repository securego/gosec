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

func TestProcessPkgSingleFile(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)

	file := filepath.Join("fixtures/pkg1", "file1.go")
	err := analyzer.ProcessPkg("pkg1", file)
	if err != nil {
		t.Errorf("Failed to process a package composed of a single file: %v\n", err)
	}
}

func TestProcessPkgMultipleFiles(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)

	file1 := filepath.Join("fixtures/pkg1", "file1.go")
	file2 := filepath.Join("fixtures/pkg1", "file2.go")

	err := analyzer.ProcessPkg("pkg1", file1, file2)
	if err != nil {
		t.Errorf("Failed to process a package composed of multiple files: %v\n", err)
	}
}

func TestProcessPkgMultiplePkgs(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)

	file := filepath.Join("fixtures/pkg1", "file1.go")
	err := analyzer.ProcessPkg("pkg1", file)
	if err != nil {
		t.Errorf("Failed to process package pkg1: %v\n", err)
	}

	file = filepath.Join("fixtures/pkg2", "file1.go")
	err = analyzer.ProcessPkg("pkg2", file)
	if err != nil {
		t.Errorf("Failed to process package pkg2: %v\n", err)
	}
}
