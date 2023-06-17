package rules

import (
	"go/ast"
	"log"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sliceOutOfBounds struct {
	sliceCaps map[string]int64 // Capacities of slices
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
	case *ast.IndexExpr:
		return s.matchIndexExpr(node, ctx)
		//case *ast.CallExpr:
		//return s.matchCallExpr(node, ctx)
	}
	return nil, nil
}

// Matches calls to make() and stores the capacity of the new slice in the map to compare against future slice usage
func (s *sliceOutOfBounds) matchSliceMake(funcCall *ast.CallExpr, sliceName string, ctx *gosec.Context) (*issue.Issue, error) {
	_, funcName, err := gosec.GetCallInfo(funcCall, ctx)
	if err != nil || funcName != "make" {
		return nil, nil
	}

	capacityArg := 1
	if len(funcCall.Args) < 2 {
		return nil, nil // No size passed
	} else if len(funcCall.Args) == 2 {
		capacityArg = 1
	} else if len(funcCall.Args) == 3 {
		capacityArg = 2
	} else {
		return nil, nil // Unexpected, args should always be 2 or 3
	}

	// Check and get the capacity of the slice passed to make. It must be a literal value, since we aren't evaluating the expression.
	sliceCapLit, ok := funcCall.Args[capacityArg].(*ast.BasicLit)
	if !ok {
		return nil, nil
	}

	sliceCap, err := gosec.GetInt(sliceCapLit)
	if err != nil {
		return nil, nil
	}

	s.sliceCaps[sliceName] = sliceCap
	return nil, nil
}

// Matches slice assignments, calculates capacity of slice if possible to store it in map
func (s *sliceOutOfBounds) matchSliceAssignment(node *ast.SliceExpr, sliceName string, ctx *gosec.Context) (*issue.Issue, error) {
	// First do the normal match that verifies the slice expr is not out of bounds
	if i, err := s.matchSliceExpr(node, ctx); err != nil {
		return i, err
	}

	// Now that the assignment is (presumably) successfully, we can calculate the capacity and add this new slice to the map
	// Get ident to get name
	ident, ok := node.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	// Get cap of old slice to calculate this new slice's cap
	oldCap, ok := s.sliceCaps[ident.Name]
	if !ok {
		return nil, nil
	}
	log.Print(ident.Name, " OLD CAP--", oldCap)

	// Get and check low value
	lowIdent, ok := node.Low.(*ast.BasicLit)
	if ok && lowIdent != nil {
		low, _ := gosec.GetInt(lowIdent)

		newCap := oldCap - low
		log.Print(ident.Name, " NEW CAP--", newCap)
		s.sliceCaps[sliceName] = newCap
	} else if lowIdent == nil { // If no lower bound, capacity will be same
		s.sliceCaps[sliceName] = oldCap
	}

	log.Print(s.sliceCaps)

	return nil, nil
}

func (s *sliceOutOfBounds) matchAssign(node *ast.AssignStmt, ctx *gosec.Context) (*issue.Issue, error) {
	// Check RHS for calls to make() so we can get the actual size of the slice
	for it, i := range node.Rhs {
		// Get the slice name so we can associate the cap with the slice in the map
		sliceIdent, ok := node.Lhs[it].(*ast.Ident)
		if !ok {
			return nil, nil
		}
		sliceName := sliceIdent.Name

		switch expr := i.(type) {
		case *ast.CallExpr: // Check for and handle call to make()
			return s.matchSliceMake(expr, sliceName, ctx)
		case *ast.SliceExpr: // Handle assignments to a slice
			return s.matchSliceAssignment(expr, sliceName, ctx)
		}
	}
	return nil, nil
}

func (s *sliceOutOfBounds) matchSliceExpr(node *ast.SliceExpr, ctx *gosec.Context) (*issue.Issue, error) {
	// First get the slice name so we can check the size in our map
	ident, ok := node.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	// Get slice cap from the map to compare it against high and low
	sliceCap, ok := s.sliceCaps[ident.Name]
	if !ok {
		return nil, nil // Slice is not present in map, so doing nothing
	}

	// Get and check high value
	highIdent, ok := node.High.(*ast.BasicLit)
	if ok && highIdent != nil {
		high, _ := gosec.GetInt(highIdent)
		if high > sliceCap {
			return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	// Get and check low value
	lowIdent, ok := node.Low.(*ast.BasicLit)
	if ok && lowIdent != nil {
		low, _ := gosec.GetInt(lowIdent)
		if low > sliceCap {
			return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	return nil, nil
}

func (s *sliceOutOfBounds) matchIndexExpr(node *ast.IndexExpr, ctx *gosec.Context) (*issue.Issue, error) {
	// First get the slice name so we can check the size in our map
	ident, ok := node.X.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	// Get slice cap from the map to compare it against high and low
	sliceSize, ok := s.sliceCaps[ident.Name]
	if !ok {
		return nil, nil // Slice is not present in map, so doing nothing
	}

	// Get the index literal
	indexIdent, ok := node.Index.(*ast.BasicLit)
	if ok && indexIdent != nil {
		index, _ := gosec.GetInt(indexIdent)
		if index >= sliceSize {
			return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	return nil, nil
}

//func (s *sliceOutOfBounds) matchAssign(node *ast.AssignStmt, ctx *gosec.Context) (*issue.Issue, error) {
//}

func NewSliceBoundCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &sliceOutOfBounds{
		sliceCaps: make(map[string]int64),
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Potentially accessing slice out of bounds",
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.SliceExpr)(nil), (*ast.IndexExpr)(nil), (*ast.CallExpr)(nil)}
}
