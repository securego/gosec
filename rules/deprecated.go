package rules

import (
	"go/ast"
	"regexp"

	"github.com/securego/gosec/v2"
)

type usingDeprecated struct {
	gosec.MetaData
	depRe *regexp.Regexp
}

func (r *usingDeprecated) ID() string {
	return r.MetaData.ID
}

func (r *usingDeprecated) Match(node ast.Node, ctx *gosec.Context) (gi *gosec.Issue, err error) {
	callExpr, callExprOk := node.(*ast.CallExpr)
	if !callExprOk {
		// fmt.Printf("impossible to check not call expression at %v\n", node.Pos())
		return nil, nil
	}

	funcDecl, funcDeclErr := gosec.FindFuncDecl(callExpr, ctx)
	if funcDeclErr != nil {
		return nil, nil
	}

	if funcDecl.Doc == nil {
		return nil, nil
	}

	for _, comment := range funcDecl.Doc.List {
		if comment == nil {
			continue
		}

		if r.depRe.MatchString(comment.Text) {
			return gosec.NewIssue(ctx, node, r.ID(), r.What, r.Severity, r.Confidence), nil
		}
	}

	return nil, nil
}

// NewUsingDeprecated rule detects the use of the deprecated package. This is only
// really useful for auditing purposes.
func NewUsingDeprecated(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	depRe, _ := regexp.Compile(`(?i)//\s*deprecated`)
	return &usingDeprecated{
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Use of deprecated calls is unsafe",
			Severity:   gosec.High,
			Confidence: gosec.High,
		},
		depRe: depRe,
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
