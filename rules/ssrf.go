package rules

import (
	"github.com/GoASTScanner/gas"
	"go/ast"
	"go/types"
)

type ssrf struct {
	gas.MetaData
	gas.CallList
}

// ID returns the identifier for this rule
func (r *ssrf) ID() string {
	return r.MetaData.ID
}

// Match inspects AST nodes to determine if certain net/http methods are called with variable input
func (r *ssrf) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := r.ContainsCallExpr(n, c); node != nil {
		for _, arg := range node.Args {
			if ident, ok := arg.(*ast.Ident); ok {
				obj := c.Info.ObjectOf(ident)
				if _, ok := obj.(*types.Var); ok && !gas.TryResolve(ident, c) {
					return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewSSRFCheck detects cases where HTTP requests are sent
func NewSSRFCheck(id string, conf gas.Config) (gas.Rule, []ast.Node) {
	rule := &ssrf{
		CallList: gas.NewCallList(),
		MetaData: gas.MetaData{
			ID:         id,
			What:       "Potential HTTP request made with variable url",
			Severity:   gas.Medium,
			Confidence: gas.Medium,
		},
	}
	rule.Add("net/http", "Do", "Get", "Head", "Post", "PostForm", "RoundTrip")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
