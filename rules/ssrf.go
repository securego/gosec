package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec"
)

type ssrf struct {
	gosec.MetaData
	gosec.CallList
}

// ID returns the identifier for this rule
func (r *ssrf) ID() string {
	return r.MetaData.ID
}

// ResolveVar tries to resolve the arguments of a callexpression
func (r *ssrf) ResolveVar(n *ast.CallExpr, c *gosec.Context) bool {
  // iterate through the all arguments (almost always 1) of the call expression
  for _, arg := range n.Args {
    if ident, ok := arg.(*ast.Ident); ok {
      obj := c.Info.ObjectOf(ident)
      if _, ok := obj.(*types.Var); ok && !gosec.TryResolve(ident, c) {
        return true
      }
    }
  }
  return false
}

// Match inspects AST nodes to determine if certain net/http methods are called with variable input
func (r *ssrf) Match(n ast.Node, c *gosec.Context) (*gosec.Issue, error) {
	// Call expression is using http package directly
	if node := r.ContainsCallExpr(n, c); node != nil {
    if r.ResolveVar(node, c) {
      return gosec.NewIssue(c, n, r.ID(), r.What, r.Severity, r.Confidence), nil
    }
	}
	// Look at the last selector identity for methods matching net/http's
	if node, ok := n.(*ast.CallExpr); ok {
		if selExpr, ok := node.Fun.(*ast.SelectorExpr); ok {
			// Pull last selector's identity name
				if r.Contains("net/http", selExpr.Sel.Name) {
          // Try and resolve arguments
          if r.ResolveVar(node, c) {
					  return gosec.NewIssue(c, n, r.ID(), r.What, r.Severity, r.Confidence), nil
				  }
      }
		}
	}
	return nil, nil
}

// NewSSRFCheck detects cases where HTTP requests are sent
func NewSSRFCheck(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &ssrf{
		CallList: gosec.NewCallList(),
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Potential HTTP request made with variable url",
			Severity:   gosec.Medium,
			Confidence: gosec.Medium,
		},
	}
	rule.AddAll("net/http", "Do", "Get", "Head", "Post", "PostForm", "RoundTrip")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
