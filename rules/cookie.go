package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type insecureCookie struct {
	issue.MetaData
}

func (r *insecureCookie) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	comp, ok := n.(*ast.CompositeLit)
	if !ok {
		return nil, nil
	}
	sel, ok := comp.Type.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}
	if ident.Name != "http" || sel.Sel.Name != "Cookie" {
		return nil, nil
	}
	secureSet := false
	httpOnlySet := false
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		val, ok := kv.Value.(*ast.Ident)
		if !ok {
			continue
		}
		if key.Name == "Secure" && val.Name == "true" {
			secureSet = true
		}
		if key.Name == "HttpOnly" && val.Name == "true" {
			httpOnlySet = true
		}
	}
	if !secureSet || !httpOnlySet {
		return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
	}
	return nil, nil
}

func NewInsecureCookie(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &insecureCookie{
		MetaData: issue.NewMetaData(
			id,
			"Cookie does not have Secure and HttpOnly flags set to true.",
			issue.Medium,
			issue.High,
		),
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}
