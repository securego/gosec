package rules

import (
	"go/ast"
	"go/token"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

// urlJoin flags url.JoinPath and (*url.URL).JoinPath calls whose path
// elements are not known to be escaped: string literals, constant
// expressions, url.PathEscape calls and additive combinations of those
// are considered safe, everything else is reported.
type urlJoin struct {
	callListRule
	methodCalls  gosec.CallList
	escapedCalls gosec.CallList
}

// Match inspects CallExpr nodes for url.JoinPath calls whose element
// arguments are not literals, constants, or url.PathEscape calls.
func (r *urlJoin) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}
	var elems []ast.Expr
	switch {
	case r.calls.ContainsPkgCallExpr(n, c, false) != nil:
		// Package-level url.JoinPath(base, elem ...string): the base is the
		// URL to join onto, only the trailing elements are path segments.
		elems = call.Args[1:]
	case r.methodCalls.ContainsCallExpr(n, c) != nil:
		// (*url.URL).JoinPath(elem ...string): every argument is a segment.
		elems = call.Args
	}
	for _, elem := range elems {
		if !r.isEscaped(elem, c) {
			return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

// isEscaped reports whether the expression is known to produce an already
// escaped path segment: string literals and constant expressions are inert,
// url.PathEscape is the documented escaper for path segments, and
// concatenation preserves the safety of its operands.
func (r *urlJoin) isEscaped(e ast.Expr, c *gosec.Context) bool {
	switch node := e.(type) {
	case *ast.BasicLit:
		return node.Kind == token.STRING
	case *ast.ParenExpr:
		return r.isEscaped(node.X, c)
	case *ast.CallExpr:
		if r.escapedCalls.ContainsPkgCallExpr(node, c, false) != nil {
			return true
		}
	case *ast.BinaryExpr:
		return node.Op == token.ADD &&
			r.isEscaped(node.X, c) &&
			r.isEscaped(node.Y, c)
	}
	if c.Info != nil {
		if tv, ok := c.Info.Types[e]; ok && tv.Value != nil {
			return true
		}
	}
	return false
}

// NewURLJoinPath detects url.JoinPath and (*url.URL).JoinPath calls whose
// path elements are not literals, constants, or url.PathEscape calls.
func NewURLJoinPath(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &urlJoin{
		callListRule: newCallListRule(id, "Potential path traversal via unescaped url.JoinPath element", issue.Medium, issue.Medium),
		methodCalls:  gosec.NewCallList(),
		escapedCalls: gosec.NewCallList(),
	}
	rule.AddAll("net/url", "JoinPath")
	rule.methodCalls.Add("*net/url.URL", "JoinPath")
	rule.methodCalls.Add("net/url.URL", "JoinPath")
	rule.escapedCalls.AddAll("net/url", "PathEscape")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
