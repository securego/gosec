package gosec_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
)

func TestLargePackageKeepsCrossFileTypesAndFindings(t *testing.T) {
	root := filepath.Join(t.TempDir(), strings.Repeat("package", 12))
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, source string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/largepackage\n\ngo 1.26\n")
	const files = 256
	argumentBytes := 0
	for i := range files {
		name := fmt.Sprintf("value_%03d.go", i)
		argumentBytes += len(filepath.Join(root, name)) + 1
		imports, body := "", "return 1"
		if i+1 < files {
			body = fmt.Sprintf("return Value%03d()", i+1)
		}
		if i == 0 {
			imports = "import \"os\"\n"
			body = "_ = os.Chmod(\"example\", 0777); " + body
		}
		write(name, fmt.Sprintf("package largepackage\n%sfunc Value%03d() int { %s }\n", imports, i, body))
	}
	// go/packages chunks filename arguments above this boundary. Each chunk
	// would be an incomplete package because functions refer to the next file.
	if argumentBytes <= 16383 {
		t.Fatalf("fixture is too small: %d argument bytes", argumentBytes)
	}
	analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0))
	analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G302")).RulesInfo())
	if err := analyzer.Process(nil, root); err != nil {
		t.Fatal(err)
	}
	issues, metrics, loadErrors := analyzer.Report()
	if len(loadErrors) != 0 {
		t.Fatalf("complete package failed to load: %v", loadErrors)
	}
	if metrics.NumFiles != files {
		t.Fatalf("scanned %d files, want %d", metrics.NumFiles, files)
	}
	if len(issues) != 1 || issues[0].RuleID != "G302" {
		t.Fatalf("expected the insecure permission finding, got %v", issues)
	}
}

func TestPackageLoadingScansProductionAndTestsOnce(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod":              "module example.com/testpackage\n\ngo 1.26\n",
		"permissions.go":      "package testpackage\nimport \"os\"\nfunc Permissions() { _ = os.Chmod(\"production\", 0777) }\n",
		"permissions_test.go": "package testpackage\nimport (\"os\"; \"testing\")\nfunc TestPermissions(t *testing.T) { _ = os.Chmod(\"test\", 0777) }\n",
		"external_test.go":    "package testpackage_test\nimport (\"os\"; \"testing\"; \"example.com/testpackage\")\nfunc TestExternal(t *testing.T) { testpackage.Permissions(); _ = os.Chmod(\"external\", 0777) }\n",
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		scanTests bool
		want      int
	}{
		{"production", false, 1},
		{"internal-and-external", true, 3},
		{"external-only", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "external-only" {
				if err := os.Remove(filepath.Join(root, "permissions_test.go")); err != nil {
					t.Fatal(err)
				}
			}
			analyzer := gosec.NewAnalyzer(gosec.NewConfig(), tc.scanTests, false, false, 1, log.New(io.Discard, "", 0))
			analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G302")).RulesInfo())
			if err := analyzer.Process(nil, root); err != nil {
				t.Fatal(err)
			}
			issues, metrics, loadErrors := analyzer.Report()
			if len(loadErrors) != 0 {
				t.Fatalf("package failed to load: %v", loadErrors)
			}
			if len(issues) != tc.want || metrics.NumFiles != tc.want {
				t.Fatalf("issues=%d files=%d; want %d each", len(issues), metrics.NumFiles, tc.want)
			}
		})
	}
}
