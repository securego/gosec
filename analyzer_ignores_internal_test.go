package gosec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"reflect"
	"slices"
	"testing"

	"github.com/securego/gosec/v2/issue"
)

func TestIgnoresNestedRanges(t *testing.T) {
	t.Parallel()

	outer := issue.SuppressionInfo{Kind: "inSource", Justification: "outer directive"}
	inner := issue.SuppressionInfo{Kind: "inSource", Justification: "inner directive"}
	for _, innerRule := range []string{"G304", aliasOfAllRules} {
		for _, order := range []struct {
			name    string
			reverse bool
		}{
			{name: "outer first"},
			{name: "inner first", reverse: true},
		} {
			t.Run(innerRule+"/"+order.name, func(t *testing.T) {
				ignores := newIgnores()
				addOuter := func() {
					ignores.add("test.go", "9-37", map[string]issue.SuppressionInfo{"G101": outer})
				}
				addInner := func() {
					ignores.add("test.go", "24", map[string]issue.SuppressionInfo{innerRule: inner})
				}
				if order.reverse {
					addInner()
					addOuter()
				} else {
					addOuter()
					addInner()
				}

				both := map[string][]issue.SuppressionInfo{"G101": {outer}, innerRule: {inner}}
				outerOnly := map[string][]issue.SuppressionInfo{"G101": {outer}}
				none := map[string][]issue.SuppressionInfo{}
				for _, tt := range []struct {
					name string
					file string
					line string
					want map[string][]issue.SuppressionInfo
				}{
					{name: "outer finding", file: "test.go", line: "10-37", want: both},
					{name: "inner finding", file: "test.go", line: "24", want: both},
					{name: "outside inner range", file: "test.go", line: "15", want: outerOnly},
					{name: "start boundary", file: "test.go", line: "9", want: outerOnly},
					{name: "end boundary", file: "test.go", line: "37", want: outerOnly},
					{name: "before ranges", file: "test.go", line: "8", want: none},
					{name: "after ranges", file: "test.go", line: "38", want: none},
					{name: "partial overlap", file: "test.go", line: "30-40", want: none},
					{name: "other file", file: "other.go", line: "24", want: none},
				} {
					t.Run(tt.name, func(t *testing.T) {
						if got := ignores.get(tt.file, tt.line); !reflect.DeepEqual(got, tt.want) {
							t.Fatalf("unexpected suppressions: got %#v, want %#v", got, tt.want)
						}
					})
				}
			})
		}
	}
}

func TestIgnoresPreservesJustifications(t *testing.T) {
	t.Parallel()

	first := issue.SuppressionInfo{Kind: "inSource", Justification: "first directive"}
	second := issue.SuppressionInfo{Kind: "inSource", Justification: "second directive"}
	for _, line := range []string{"9-37", "24"} {
		t.Run(line, func(t *testing.T) {
			ignores := newIgnores()
			ignores.add("test.go", "9-37", map[string]issue.SuppressionInfo{"G101": first})
			ignores.add("test.go", line, map[string]issue.SuppressionInfo{"G101": second})

			got := ignores.get("test.go", "24")["G101"]
			if len(got) != 2 || !slices.Contains(got, first) || !slices.Contains(got, second) {
				t.Fatalf("expected both justifications, got %#v", got)
			}
		})
	}
}

func TestUpdateIgnoresSourceOrder(t *testing.T) {
	t.Parallel()

	const source = `package test

// #nosec G101 -- outer directive
func example() {
	// #nosec G101 -- inner directive
	println("example")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	visitor := &astVisitor{
		gosec: NewAnalyzer(NewConfig(), false, false, false, 1, log.New(io.Discard, "", 0)),
		context: &Context{
			FileSet:  fset,
			Comments: ast.NewCommentMap(fset, file, file.Comments),
		},
		stats: &Metrics{},
	}
	visitor.updateIgnores()

	want := []issue.SuppressionInfo{
		{Kind: "inSource", Justification: "outer directive"},
		{Kind: "inSource", Justification: "inner directive"},
	}
	if got := visitor.context.Ignores.get("test.go", "6")["G101"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected suppressions in source order: got %#v, want %#v", got, want)
	}
}
