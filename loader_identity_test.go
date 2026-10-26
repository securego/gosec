package gosec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPreservesModulePackageIdentity(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GO111MODULE", "on")
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/loaderfixture\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "p.go"), []byte("package pkg\n\ntype Value struct{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyzer := NewAnalyzer(nil, false, false, false, 1, nil)
	pkgs, err := analyzer.load(pkgDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want one", len(pkgs))
	}
	if len(pkgs[0].Errors) != 0 {
		t.Fatalf("package errors: %v", pkgs[0].Errors)
	}
	const want = "example.com/loaderfixture/pkg"
	if pkgs[0].PkgPath != want || pkgs[0].Types == nil || pkgs[0].Types.Path() != want {
		t.Fatalf("module identity = %q, want %q", pkgs[0].PkgPath, want)
	}
}
