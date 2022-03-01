package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
)

type traversal struct {
	gosec.MetaData
}

func (r *traversal) ID() string {
	return r.MetaData.ID
}

func (r *traversal) Match(n ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	return gosec.NewIssue(ctx, n, r.ID(), r.What, r.Severity, r.Confidence), nil
}

// NewDirectoryTraversal attempts to find the use of Http.Dir("/")
func NewDirectoryTraversal(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	//	pattern := `Http.Dir`
	return &traversal{
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Potential directory traversal",
			Confidence: gosec.Medium,
			Severity:   gosec.Medium,
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil), (*ast.BinaryExpr)(nil)}
}
