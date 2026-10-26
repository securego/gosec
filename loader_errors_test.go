package gosec

import (
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestSelectTestVariantsPreservesErrors(t *testing.T) {
	const path = "example.com/fixture"
	for _, variant := range []string{"base errors", "base ill typed", "augmented errors"} {
		t.Run(variant, func(t *testing.T) {
			base := &packages.Package{PkgPath: path}
			augmented := &packages.Package{PkgPath: path, ForTest: path}
			switch variant {
			case "base errors":
				base.Errors = []packages.Error{{Msg: "base load failure"}}
			case "base ill typed":
				base.IllTyped = true
			case "augmented errors":
				augmented.Errors = []packages.Error{{Msg: "test load failure"}}
			}
			analyzer := NewAnalyzer(nil, true, false, false, 1, nil)
			selected := analyzer.selectTestVariants([]*packages.Package{base, augmented})
			foundBase, foundAugmented := false, false
			for _, pkg := range selected {
				foundBase = foundBase || pkg == base
				foundAugmented = foundAugmented || pkg == augmented
			}
			if !foundAugmented {
				t.Fatal("test-augmented package and its errors were discarded")
			}
			if variant != "augmented errors" && !foundBase {
				t.Fatal("errored production base was discarded")
			}
		})
	}
}
