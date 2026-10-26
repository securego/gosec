package gosec_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
)

func TestProcessDoesNotDuplicateProductionFindingsWhenScanningTests(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GO111MODULE", "on")
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	writeProcessFixture(t, filepath.Join(root, "go.mod"), "module example.com/processfixture\n\ngo 1.21\n")
	writeProcessFixture(t, filepath.Join(pkgDir, "production.go"), g401Fixture("pkg", "Production"))
	writeProcessFixture(t, filepath.Join(pkgDir, "internal_test.go"), g401Fixture("pkg", "Internal"))
	writeProcessFixture(t, filepath.Join(pkgDir, "external_test.go"), g401Fixture("pkg_test", "External"))

	cases := []struct {
		name    string
		tests   bool
		expects map[string]int
	}{
		{
			name:    "production only",
			expects: map[string]int{"production.go": 1},
		},
		{
			name:    "production internal and external tests exactly once",
			tests:   true,
			expects: map[string]int{"production.go": 1, "internal_test.go": 1, "external_test.go": 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := gosec.NewAnalyzer(nil, tc.tests, false, false, 1, nil)
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())
			if err := analyzer.Process(nil, pkgDir); err != nil {
				t.Fatal(err)
			}
			issues, _, loadErrors := analyzer.Report()
			if len(loadErrors) != 0 {
				t.Fatalf("loader errors: %v", loadErrors)
			}
			got := map[string]int{}
			for _, finding := range issues {
				if finding.RuleID == "G401" {
					got[filepath.Base(finding.File)]++
				}
			}
			if len(got) != len(tc.expects) {
				t.Fatalf("G401 findings by file = %v, want %v", got, tc.expects)
			}
			for file, want := range tc.expects {
				if got[file] != want {
					t.Fatalf("G401 findings for %s = %d, want %d; all findings: %v", file, got[file], want, got)
				}
			}
		})
	}
}

func g401Fixture(pkg, name string) string {
	return "package " + pkg + "\n\nimport \"crypto/md5\"\n\nfunc " + name + "() { _ = md5.New() }\n"
}

func writeProcessFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
