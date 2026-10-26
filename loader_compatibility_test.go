package gosec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestLoadModuleCompatibility(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GO111MODULE", "on")
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	writeLoaderFixture(t, filepath.Join(root, "go.mod"), "module example.com/loaderfixture\n\ngo 1.21\n")
	writeLoaderFixture(t, filepath.Join(pkgDir, "production.go"), "package pkg\n\ntype Production struct{}\n")
	writeLoaderFixture(t, filepath.Join(pkgDir, "tagged.go"), "//go:build loaderfixture\n\npackage pkg\n\ntype Tagged struct{}\n")
	writeLoaderFixture(t, filepath.Join(pkgDir, "production_test.go"), "package pkg\n\nimport \"testing\"\n\nfunc TestProduction(t *testing.T) {}\n")
	writeLoaderFixture(t, filepath.Join(pkgDir, "external_test.go"), "package pkg_test\n\nimport \"testing\"\n\nfunc TestExternal(t *testing.T) {}\n")

	production := filepath.Join(pkgDir, "production.go")
	tagged := filepath.Join(pkgDir, "tagged.go")
	internalTest := filepath.Join(pkgDir, "production_test.go")
	externalTest := filepath.Join(pkgDir, "external_test.go")
	cases := []struct {
		name   string
		tests  bool
		tags   []string
		want   []string
		absent []string
	}{
		{"production without tests or tag", false, nil, []string{production}, []string{tagged, internalTest, externalTest}},
		{"production with tag", false, []string{"loaderfixture"}, []string{production, tagged}, []string{internalTest, externalTest}},
		{"tests with external package without tag", true, nil, []string{production, internalTest, externalTest}, []string{tagged}},
		{"tests with external package and tag", true, []string{"loaderfixture"}, []string{production, tagged, internalTest, externalTest}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLoadFiles(t, pkgDir, tc.tests, tc.tags, tc.want, tc.absent)
		})
	}
}

func TestLoadGOPATHCompatibility(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GO111MODULE", "off")
	gopath := t.TempDir()
	pkgDir := filepath.Join(gopath, "src", "example.com", "gopathfixture", "pkg")
	t.Setenv("GOPATH", gopath)
	production := filepath.Join(pkgDir, "production.go")
	writeLoaderFixture(t, production, "package pkg\n\ntype Production struct{}\n")
	assertLoadFiles(t, pkgDir, false, nil, []string{production}, nil)
}

func TestLoadCGOCompatibility(t *testing.T) {
	if !loaderCGOEnabled(t) {
		t.Skip("CGO_ENABLED is not 1; cgo fixture is unsupported in this test environment")
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GO111MODULE", "on")
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	writeLoaderFixture(t, filepath.Join(root, "go.mod"), "module example.com/cgofixture\n\ngo 1.21\n")
	production := filepath.Join(pkgDir, "production.go")
	cgoFile := filepath.Join(pkgDir, "cgo.go")
	writeLoaderFixture(t, production, "package pkg\n\ntype Production struct{}\n")
	writeLoaderFixture(t, cgoFile, "package pkg\n\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\n\nfunc Cgo() {}\n")
	assertLoadFiles(t, pkgDir, false, nil, []string{production, cgoFile}, nil)
}

func assertLoadFiles(t *testing.T, pkgDir string, tests bool, tags, want, absent []string) {
	t.Helper()
	analyzer := NewAnalyzer(nil, tests, false, false, 1, nil)
	pkgs, err := analyzer.load(pkgDir, tags)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		if len(pkg.Errors) != 0 {
			t.Fatalf("package %q errors: %v", pkg.PkgPath, pkg.Errors)
		}
	}
	for _, file := range want {
		if !loaderPackagesContainGoFile(t, pkgs, file) {
			t.Fatalf("loaded packages do not contain %s", file)
		}
	}
	for _, file := range absent {
		if loaderPackagesContainGoFile(t, pkgs, file) {
			t.Fatalf("loaded packages unexpectedly contain %s", file)
		}
	}
}

func loaderCGOEnabled(t *testing.T) bool {
	t.Helper()
	output, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	if err != nil {
		t.Fatalf("determine CGO_ENABLED: %v", err)
	}
	return strings.TrimSpace(string(output)) == "1"
}

func writeLoaderFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loaderPackagesContainGoFile(t *testing.T, pkgs []*packages.Package, want string) bool {
	t.Helper()
	want = loaderCanonicalPath(t, want)
	for _, pkg := range pkgs {
		for _, file := range pkg.GoFiles {
			if loaderCanonicalPath(t, file) == want {
				return true
			}
		}
	}
	return false
}

func loaderCanonicalPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return filepath.Clean(resolved)
}
