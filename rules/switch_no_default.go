package rules

import (
	"fmt"
	"go/ast"

	"github.com/securego/gosec/v2"
)

type usingSwitchNoDefault struct {
	gosec.MetaData
}

func (r *usingSwitchNoDefault) ID() string {
	return r.MetaData.ID
}

func (r *usingSwitchNoDefault) Match(node ast.Node, ctx *gosec.Context) (gi *gosec.Issue, err error) {
	switchStmt, switchExprOk := node.(*ast.SwitchStmt)
	if !switchExprOk {
		// fmt.Printf("impossible to check not call expression at %v\n", node.Pos())
		return nil, nil
	}

	if switchStmt.Body == nil || switchStmt.Body.List == nil {
		fmt.Printf("switch at %v has empty body list \n", switchStmt.Pos())
		return nil, nil
	}

	hasDefault := false
	for _, caseClausePtr := range switchStmt.Body.List {
		if caseClause, ok := caseClausePtr.(*ast.CaseClause); ok {
			if caseClause.List == nil {
				hasDefault = true
			}
		}
	}
	if !hasDefault {
		return gosec.NewIssue(ctx, node, r.ID(), r.What, r.Severity, r.Confidence), nil
	}

	return nil, nil
}

// NewUsingSwitchNoDefault rule detects the use of switch without default block.
func NewUsingSwitchNoDefault(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return &usingSwitchNoDefault{
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Use of switch without default block is dangerous",
			Severity:   gosec.Low,
			Confidence: gosec.High,
		},
	}, []ast.Node{(*ast.SwitchStmt)(nil)}
}
