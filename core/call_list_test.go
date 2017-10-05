package core

import (
	"go/ast"
	"testing"
)

type callListRule struct {
	MetaData
	callList CallList
	matched  int
}

func (r *callListRule) ID() string {
	return r.MetaData.ID
}

func (r *callListRule) Match(n ast.Node, c *Context) (gi *Issue, err error) {
	if r.callList.ContainsCallExpr(n, c) {
		r.matched += 1
	}
	return nil, nil
}

func TestCallListContainsCallExpr(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := NewAnalyzer(config, nil)
	calls := NewCallList()
	calls.AddAll("bytes.Buffer", "Write", "WriteTo")
	rule := &callListRule{
		MetaData: MetaData{
			ID:         "TEST",
			Severity:   Low,
			Confidence: Low,
			What:       "A dummy rule",
		},
		callList: calls,
		matched:  0,
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
	if rule.matched != 1 {
		t.Errorf("Expected to match a bytes.Buffer.Write call")
	}
}

func TestCallListContains(t *testing.T) {
	callList := NewCallList()
	callList.Add("fmt", "Printf")
	if !callList.Contains("fmt", "Printf") {
		t.Errorf("Expected call list to contain fmt.Printf")
	}
}
