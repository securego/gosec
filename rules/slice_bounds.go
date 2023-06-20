package rules

import (
	"fmt"
	"go/ast"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

// sliceOutOfBounds is a rule which checks for slices which are accessed outside their capacity,
// either through indexing it out of bounds or through slice expressions whose low or high index
// are out of bounds.
type sliceOutOfBounds struct {
	sliceCaps       map[*ast.CallExpr]map[string]*int64 // Capacities of slices. Maps function call -> var name -> value.
	currentScope    *types.Scope                        // Current scope. Map is cleared when scope changes.
	currentFuncName string                              // Current function.
	funcCallArgs    map[string][]*int64                 // Caps to load once a func declaration is scanned.
	issue.MetaData                                      // Metadata for this rule.
}

// ID returns the rule ID for sliceOutOfBounds: G602.
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
		s.loadArgCaps(node)
	case *ast.CallExpr:
		if _, ok := node.Fun.(*ast.FuncLit); ok {
			// Do nothing with func literals for now.
			break
		}

		sliceMap := make(map[string]*int64)
		s.sliceCaps[node] = sliceMap
		s.setupCallArgCaps(node, ctx)
	}
	return nil, nil
}

// updateSliceCaps takes in a variable name and a map of calls we are updating the variables for to the updated values
// and will add it to the sliceCaps map.
func (s *sliceOutOfBounds) updateSliceCaps(varName string, caps map[*ast.CallExpr]*int64) {
	for callExpr, cap := range caps {
		s.sliceCaps[callExpr][varName] = cap
	}
}

// getAllCalls returns all CallExprs that are calls to the given function.
func (s *sliceOutOfBounds) getAllCalls(funcName string, ctx *gosec.Context) []*ast.CallExpr {
	calls := []*ast.CallExpr{}

	for callExpr := range s.sliceCaps {
		if callExpr != nil {
			// Compare the names of the function the code is scanning with the current call we are iterating over
			_, callFuncName, err := gosec.GetCallInfo(callExpr, ctx)
			if err != nil {
				continue
			}

			if callFuncName == funcName {
				calls = append(calls, callExpr)
			}
		}
	}
	return calls
}

// getSliceCapsForFunc gets all the capacities for slice with given name that are stored for each call to the passed function.
func (s *sliceOutOfBounds) getSliceCapsForFunc(funcName string, varName string, ctx *gosec.Context) map[*ast.CallExpr]*int64 {
	caps := make(map[*ast.CallExpr]*int64)

	calls := s.getAllCalls(funcName, ctx)
	for _, call := range calls {
		if callCaps, ok := s.sliceCaps[call]; ok {
			caps[call] = callCaps[varName]
		}
	}

	return caps
}

// setupCallArgCaps evaluates and saves the caps for any slices in the args so they can be validated when the function is scanned.
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

			// Simplifying assumption: use the lowest capacity. Storing all possible capacities for slices passed
			// to a function call would catch the most issues, but would require a data structure like a stack and a
			// reworking of the code for scanning itself. Use the lowest capacity, as this would be more likely to
			// raise an issue for being out of bounds.
			var lowestCap *int64
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
				funcCallArgs = append(funcCallArgs, nil)
				continue
			}

			// Now create a map of just this value to add it to the sliceCaps
			funcCallArgs = append(funcCallArgs, lowestCap)
		case *ast.Ident:
			ident := arg.(*ast.Ident)
			caps := s.getSliceCapsForFunc(s.currentFuncName, ident.Name, ctx)

			var lowestCap *int64
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
				funcCallArgs = append(funcCallArgs, nil)
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

// loadArgCaps loads caps that were saved for a call to this function.
func (s *sliceOutOfBounds) loadArgCaps(funcDecl *ast.FuncDecl) {
	sliceMap := make(map[string]*int64)
	funcName := funcDecl.Name.Name

	// Create a dummmy call expr for the new function. This is so we can still store args for
	// functions which are not explicitly called in the code by other functions (specifically, main).
	ident := ast.NewIdent(funcName)
	dummyCallExpr := ast.CallExpr{
		Fun: ident,
	}

	argCaps, ok := s.funcCallArgs[funcName]
	if !ok || len(argCaps) == 0 {
		s.sliceCaps[&dummyCallExpr] = sliceMap
		return
	}

	params := funcDecl.Type.Params.List
	if len(params) > len(argCaps) {
		return // Length of params and args doesn't match, so don't do anything with this.
	}

	for it := range params {
		capacity := argCaps[it]
		if capacity == nil {
			continue
		}

		if len(params[it].Names) == 0 {
			continue
		}

		if paramName := params[it].Names[0]; paramName != nil {
			sliceMap[paramName.Name] = capacity
		}
	}

	s.sliceCaps[&dummyCallExpr] = sliceMap
}

// matchSliceMake matches calls to make() and stores the capacity of the new slice in the map to compare against future slice usage.
func (s *sliceOutOfBounds) matchSliceMake(funcCall *ast.CallExpr, sliceName string, ctx *gosec.Context) (*issue.Issue, error) {
	_, funcName, err := gosec.GetCallInfo(funcCall, ctx)
	if err != nil || funcName != "make" {
		return nil, nil
	}

	var capacityArg int
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

	capacity, err := gosec.GetInt(sliceCapLit)
	if err != nil {
		return nil, nil
	}

	caps := s.getSliceCapsForFunc(s.currentFuncName, sliceName, ctx)
	for callExpr := range caps {
		caps[callExpr] = &capacity
	}

	s.updateSliceCaps(sliceName, caps)
	return nil, nil
}

// evaluateSliceExpr takes a slice expression and evaluates what the capacity of said slice is for each of the
// calls to the current function. Returns map of the call expressions of each call to the current function to
// the evaluated capacities.
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

// matchSliceAssignment matches slice assignments, calculates capacity of slice if possible to store it in map.
func (s *sliceOutOfBounds) matchSliceAssignment(node *ast.SliceExpr, sliceName string, ctx *gosec.Context) (*issue.Issue, error) {
	// First do the normal match that verifies the slice expr is not out of bounds
	if i, err := s.matchSliceExpr(node, ctx); err != nil {
		return i, fmt.Errorf("There was an error while matching a slice expression to check slice bounds for %s: %w", sliceName, err)
	}

	// Now that the assignment is (presumably) successfully, we can calculate the capacity and add this new slice to the map
	caps := s.evaluateSliceExpr(node, ctx)
	s.updateSliceCaps(sliceName, caps)

	return nil, nil
}

// matchAssign matches checks if an assignment statement is making a slice, or if it is assigning a slice.
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

// matchSliceExpr validates that a given slice expression (eg, slice[10:30]) is not out of bounds.
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

// matchIndexExpr validates that an index into a slice is not out of bounds.
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

// NewSliceBoundCheck attempts to find any slices being accessed out of bounds
// by reslicing or by being indexed.
func NewSliceBoundCheck(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	sliceMap := make(map[*ast.CallExpr]map[string]*int64)

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
