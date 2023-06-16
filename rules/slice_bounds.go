package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sliceOutOfBounds struct {
	calls      gosec.CallList
	sliceSizes map[string]int64
	issue.MetaData
}

func (s *sliceOutOfBounds) ID() string {
	return s.MetaData.ID
}

func (s *sliceOutOfBounds) Match(node ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := node.(type) {
	case *ast.AssignStmt:
		return s.matchAssign(node, ctx)
	case *ast.SliceExpr:
		return s.matchSliceExpr(node, ctx)
	}
	return nil, nil
}

func (s *sliceOutOfBounds) matchAssign(node *ast.AssignStmt, ctx *gosec.Context) (*issue.Issue, error) {
	// Check RHS for calls to make() so we can get the actual size of the slice
	for it, i := range node.Rhs {
		funcCall, ok := i.(*ast.CallExpr)
		if !ok {
			return nil, nil
		}

		_, funcName, err := gosec.GetCallInfo(i, ctx)
		if err != nil || funcName != "make" {
			return nil, nil
		}

		if len(funcCall.Args) < 2 {
			return nil, nil // No size passed
		}

		// Check and get the size of the slice passed to make. It must be a literal value, since we aren't evaluating the expression.
		sliceSizeLit, ok := funcCall.Args[1].(*ast.BasicLit)
		if !ok {
			return nil, nil
		}

		sliceSize, err := gosec.GetInt(sliceSizeLit)
		if err != nil {
			return nil, nil
		}

		// Get the slice name so we can associate the size with the slice in the map
		sliceIdent, ok := node.Lhs[it].(*ast.Ident)
		if !ok {
			return nil, nil
		}

		sliceName := sliceIdent.Name
		if err != nil {
			return nil, nil
		}

		s.sliceSizes[sliceName] = sliceSize
	}
	return nil, nil
}

func (s *sliceOutOfBounds) matchSliceExpr(node *ast.SliceExpr, ctx *gosec.Context) (*issue.Issue, error) {
	// First get the slice name so we can check the size in our map
	ident, ok := node.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	// Get slice size from the map to compare it against high and low
	sliceSize, ok := s.sliceSizes[ident.Name]
	if !ok {
		return nil, nil // Slice is not present in map, so doing nothing
	}

	// Get and check low value
	highIdent, ok := node.High.(*ast.BasicLit)
	if ok && highIdent != nil {
		high, _ := gosec.GetInt(highIdent)
		if high > sliceSize {
			return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	// Get and check low value
	lowIdent, ok := node.Low.(*ast.BasicLit)
	if ok && lowIdent != nil {
		low, _ := gosec.GetInt(lowIdent)
		if low > sliceSize {
			return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	return nil, nil
}

func NewSliceBoundCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &sliceOutOfBounds{
		sliceSizes: make(map[string]int64),
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Potentially accessing slice out of bounds",
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil), (*ast.BinaryExpr)(nil), (*ast.SliceExpr)(nil)}
}
