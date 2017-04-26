package gas

import (
	"go/ast"
	"testing"
)

type dummyCallback func(ast.Node, *Context, string, ...string) (*ast.CallExpr, bool)

type dummyRule struct {
	MetaData
	pkgOrType      string
	funcsOrMethods []string
	callback       dummyCallback
	callExpr       []ast.Node
	matched        int
}

func (r *dummyRule) Match(n ast.Node, c *Context) (gi *Issue, err error) {
	if callexpr, matched := r.callback(n, c, r.pkgOrType, r.funcsOrMethods...); matched {
		r.matched += 1
		r.callExpr = append(r.callExpr, callexpr)
	}
	return nil, nil
}

func TestMatchCallByType(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)
	rule := &dummyRule{
		MetaData: MetaData{
			Severity:   Low,
			Confidence: Low,
			What:       "A dummy rule",
		},
		pkgOrType:      "bytes.Buffer",
		funcsOrMethods: []string{"Write"},
		callback:       MatchCallByType,
		callExpr:       []ast.Node{},
		matched:        0,
	}
	analyzer.AddRule(rule, []ast.Node{(*ast.CallExpr)(nil)})
	source := `
	package main
	import (
		"bytes"
		"fmt"
	)
	func main() {
		var b bytes.Buffer
		b.Write([]byte("Hello "))
		fmt.Fprintf(&b, "world!")
	}`

	analyzer.ProcessSource("dummy.go", source)
	if rule.matched != 1 || len(rule.callExpr) != 1 {
		t.Errorf("Expected to match a bytes.Buffer.Write call")
	}

	typeName, callName, err := GetCallInfo(rule.callExpr[0], analyzer.context)
	if err != nil {
		t.Errorf("Unable to resolve call info: %v\n", err)
	}
	if typeName != "bytes.Buffer" {
		t.Errorf("Expected: %s, Got: %s\n", "bytes.Buffer", typeName)
	}
	if callName != "Write" {
		t.Errorf("Expected: %s, Got: %s\n", "Write", callName)
	}

}
