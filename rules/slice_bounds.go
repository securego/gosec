package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sliceOutOfBounds struct {
	sliceCaps       map[*ast.CallExpr]map[string]*int64 // Capacities of slices. Maps function call -> var name -> value
	currentScope    *types.Scope                        // Current scope. Map is cleared when scope changes.
	currentFuncName string                              // Current function
	funcCallArgs    map[string][]*int64                 // Caps to load once a func declaration is scanned
	issue.MetaData
}

func (s *sliceOutOfBounds) ID() string {
	return s.MetaData.ID
}

func (s *sliceOutOfBounds) Match(node ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	if s.currentScope == nil {
		s.currentScope = ctx.Pkg.Scope()
	} else if s.currentScope != ctx.Pkg.Scope() {
		s.currentScope = ctx.Pkg.Scope()

		// Clear slice map, since we are in a new scope
		sliceMapNil := make(map[string]*int64)
		sliceCaps := make(map[*ast.CallExpr]map[string]*int64)
		sliceCaps[nil] = sliceMapNil
		s.sliceCaps = sliceCaps
	}

	switch node := node.(type) {
	case *ast.AssignStmt:
		return s.matchAssign(node, ctx)
	case *ast.SliceExpr:
		return s.matchSliceExpr(node, ctx)
	case *ast.IndexExpr:
		return s.matchIndexExpr(node, ctx)
	case *ast.FuncDecl:
		s.currentFuncName = node.Name.Name
		s.loadArgCaps(node, ctx)
	case *ast.CallExpr:
		sliceMap := make(map[string]*int64)
		s.sliceCaps[node] = sliceMap
		s.setupCallArgCaps(node, ctx)
	}
	return nil, nil
}

func (s *sliceOutOfBounds) updateSliceCaps(varName string, caps map[*ast.CallExpr]*int64) {
	for callExpr, cap := range caps {
		s.sliceCaps[callExpr][varName] = cap
	}
}

// Get all calls for the current function
func (s *sliceOutOfBounds) getAllCalls(funcName string, ctx *gosec.Context) []*ast.CallExpr {
	calls := []*ast.CallExpr{}

	for callExpr, _ := range s.sliceCaps {
		if callExpr != nil {
			// Compare the names of the function the code is scanning with the current call we are iterating over
			_, funcName, err := gosec.GetCallInfo(callExpr, ctx)
			if err != nil {
				continue
			}

			if funcName == s.currentFuncName {
				calls = append(calls, callExpr)
			}
		} else {
			calls = append(calls, callExpr)
		}
	}
	return calls
}

// Gets all the capacities for slice with given name that are stored for each call to the current function we are looking at
func (s *sliceOutOfBounds) getSliceCapsForFunc(funcName string, varName string, ctx *gosec.Context) map[*ast.CallExpr]*int64 {
	caps := make(map[*ast.CallExpr]*int64)

	calls := s.getAllCalls(funcName, ctx)
	for _, call := range calls {
		caps[call] = s.sliceCaps[call][varName]
	}

	return caps
}

// Evaluate and save the caps for any slices in the args so they can be validated when the function is scanned
func (s *sliceOutOfBounds) setupCallArgCaps(callExpr *ast.CallExpr, ctx *gosec.Context) {
	// Array of caps to be loaded once the function declaration is scanned
	funcCallArgs := []*int64{}

	// Get function name
	_, funcName, err := gosec.GetCallInfo(callExpr, ctx)
	if err != nil {
		return
	}

	for _, arg := range callExpr.Args {
		switch node := arg.(type) {
		case *ast.SliceExpr:
			caps := s.evaluateSliceExpr(node, ctx)

			// Simplifying assumption: use the lowest capacity. Storing all possibly capacities for slices passed
			// to a function call would catch the most issues, but would require a data structure like a stack and a
			// reworking of the code for scanning itself. Use the lowest capacity, as this would be more likely to
			// raise an issue for being out of bounds.
			var lowestCap *int64 = nil
			for _, cap := range caps {
				if lowestCap == nil {
					lowestCap = cap
				} else if *lowestCap > *cap {
					lowestCap = cap
				}
			}

			if lowestCap == nil {
				continue
			}

			// Now create a map of just this value to add it to the sliceCaps
			funcCallArgs = append(funcCallArgs, lowestCap)
		case *ast.Ident:
			ident := arg.(*ast.Ident)
			caps := s.getSliceCapsForFunc(funcName, ident.Name, ctx)

			var lowestCap *int64 = nil
			for _, cap := range caps {
				if cap == nil {
					continue
				}
				if lowestCap == nil {
					lowestCap = cap
				} else if *lowestCap > *cap {
					lowestCap = cap
				}
			}

			if lowestCap == nil {
				continue
			}

			// Now create a map of just this value to add it to the sliceCaps
			funcCallArgs = append(funcCallArgs, lowestCap)
		default:
			funcCallArgs = append(funcCallArgs, nil)
		}
	}
	s.funcCallArgs[funcName] = funcCallArgs
}

// Load caps that were saved for a call to this function
func (s *sliceOutOfBounds) loadArgCaps(funcDecl *ast.FuncDecl, ctx *gosec.Context) {
	sliceMap := make(map[string]*int64)
	funcName := funcDecl.Name.Name

	argCaps, ok := s.funcCallArgs[funcName]
	if !ok || len(argCaps) == 0 {
		s.sliceCaps[nil] = sliceMap
		return
	}

	params := funcDecl.Type.Params.List
	if len(params) > len(argCaps) {
		return
	}

	for it := range params {
		cap := argCaps[it]
		if cap == nil {
			continue
		}

		if len(params[it].Names) == 0 {
			continue
		}

		paramName := params[it].Names[0].Name
		sliceMap[paramName] = cap
	}

	s.sliceCaps[nil] = sliceMap
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

	cap, err := gosec.GetInt(sliceCapLit)
	if err != nil {
		return nil, nil
	}

	caps := s.getSliceCapsForFunc(s.currentFuncName, sliceName, ctx)
	for callExpr, _ := range caps {
		caps[callExpr] = &cap
	}

	s.updateSliceCaps(sliceName, caps)
	return nil, nil
}

func (s *sliceOutOfBounds) evaluateSliceExpr(node *ast.SliceExpr, ctx *gosec.Context) map[*ast.CallExpr]*int64 {
	// Get ident to get name
	ident, ok := node.X.(*ast.Ident)
	if !ok {
		return nil
	}

	// Get cap of old slice to calculate this new slice's cap
	caps := s.getSliceCapsForFunc(s.currentFuncName, ident.Name, ctx)
	for callExpr, oldCap := range caps {
		if oldCap == nil {
			continue
		}
		// Get and check low value
		lowIdent, ok := node.Low.(*ast.BasicLit)
		if ok && lowIdent != nil {
			low, _ := gosec.GetInt(lowIdent)

			newCap := *oldCap - low
			caps[callExpr] = &newCap
		} else if lowIdent == nil { // If no lower bound, capacity will be same
			continue
		}
	}

	return caps
}

// Matches slice assignments, calculates capacity of slice if possible to store it in map
func (s *sliceOutOfBounds) matchSliceAssignment(node *ast.SliceExpr, sliceName string, ctx *gosec.Context) (*issue.Issue, error) {
	// First do the normal match that verifies the slice expr is not out of bounds
	if i, err := s.matchSliceExpr(node, ctx); err != nil {
		return i, err
	}

	// Now that the assignment is (presumably) successfully, we can calculate the capacity and add this new slice to the map
	caps := s.evaluateSliceExpr(node, ctx)
	s.updateSliceCaps(sliceName, caps)

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
	caps := s.getSliceCapsForFunc(s.currentFuncName, ident.Name, ctx)

	for _, cap := range caps {
		if cap == nil {
			continue
		}

		// Get and check high value
		highIdent, ok := node.High.(*ast.BasicLit)
		if ok && highIdent != nil {
			high, _ := gosec.GetInt(highIdent)
			if high > *cap {
				return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
			}
		}

		// Get and check low value
		lowIdent, ok := node.Low.(*ast.BasicLit)
		if ok && lowIdent != nil {
			low, _ := gosec.GetInt(lowIdent)
			if low > *cap {
				return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
			}
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
	caps := s.getSliceCapsForFunc(s.currentFuncName, ident.Name, ctx)

	for _, cap := range caps {
		if cap == nil {
			continue
		}
		// Get the index literal
		indexIdent, ok := node.Index.(*ast.BasicLit)
		if ok && indexIdent != nil {
			index, _ := gosec.GetInt(indexIdent)
			if index >= *cap {
				return ctx.NewIssue(node, s.ID(), s.What, s.Severity, s.Confidence), nil
			}
		}
	}

	return nil, nil
}

func NewSliceBoundCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	sliceMapNil := make(map[string]*int64)
	sliceMap := make(map[*ast.CallExpr]map[string]*int64)
	sliceMap[nil] = sliceMapNil

	return &sliceOutOfBounds{
		sliceCaps:       sliceMap,
		currentFuncName: "",
		funcCallArgs:    make(map[string][]*int64),
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.Medium,
			What:       "Potentially accessing slice out of bounds",
		},
	}, []ast.Node{(*ast.CallExpr)(nil), (*ast.FuncDecl)(nil), (*ast.AssignStmt)(nil), (*ast.SliceExpr)(nil), (*ast.IndexExpr)(nil)}
}
