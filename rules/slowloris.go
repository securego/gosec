// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type slowloris struct {
	issue.MetaData
}

// slowlorisFileState records, for one file, which http.Server composite
// literals are bound to a variable or struct field and where it later gets a
// read timeout assigned.
type slowlorisFileState struct {
	// boundLits maps an http.Server literal to the variable or struct field it
	// is assigned to.
	boundLits map[*ast.CompositeLit]types.Object
	// timeoutAssigns holds the positions of ReadHeaderTimeout/ReadTimeout
	// assignments for each http.Server variable or struct field.
	timeoutAssigns map[types.Object][]token.Pos
}

func isReadTimeoutField(name string) bool {
	return name == "ReadHeaderTimeout" || name == "ReadTimeout"
}

// disablesTimeout reports whether expr is a constant zero or negative duration,
// which net/http treats as no timeout at all.
func disablesTimeout(expr ast.Expr, ctx *gosec.Context) bool {
	tv, ok := ctx.Info.Types[expr]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Int && constant.Sign(tv.Value) <= 0
}

func isHTTPServerType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	return t.String() == "net/http.Server"
}

func containsReadHeaderTimeout(node *ast.CompositeLit, ctx *gosec.Context) bool {
	if node == nil {
		return false
	}
	for _, elt := range node.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok {
				if isReadTimeoutField(ident.Name) && !disablesTimeout(kv.Value, ctx) {
					return true
				}
			}
		}
	}
	return false
}

// serverLiteral returns the http.Server composite literal in expr, looking
// through parentheses and a leading &.
func serverLiteral(expr ast.Expr) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	lit, _ := expr.(*ast.CompositeLit)
	return lit
}

// serverObject returns the variable or struct field that expr refers to, so
// that both srv and a.srv can be tracked.
func serverObject(expr ast.Expr, ctx *gosec.Context) types.Object {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return ctx.Info.ObjectOf(e)
	case *ast.SelectorExpr:
		return ctx.Info.ObjectOf(e.Sel)
	}
	return nil
}

func newSlowlorisFileState(ctx *gosec.Context) *slowlorisFileState {
	state := &slowlorisFileState{
		boundLits:      make(map[*ast.CompositeLit]types.Object),
		timeoutAssigns: make(map[types.Object][]token.Pos),
	}
	if ctx.Root == nil {
		return state
	}

	bind := func(lhs, rhs ast.Expr) {
		lit := serverLiteral(rhs)
		if lit == nil {
			return
		}
		if obj := serverObject(lhs, ctx); obj != nil {
			state.boundLits[lit] = obj
		}
	}

	ast.Inspect(ctx.Root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					bind(lhs, node.Rhs[i])
				}
			}
			for i, lhs := range node.Lhs {
				sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !ok || !isReadTimeoutField(sel.Sel.Name) {
					continue
				}
				if len(node.Lhs) == len(node.Rhs) && disablesTimeout(node.Rhs[i], ctx) {
					continue
				}
				obj := serverObject(sel.X, ctx)
				if obj == nil || !isHTTPServerType(obj.Type()) {
					continue
				}
				state.timeoutAssigns[obj] = append(state.timeoutAssigns[obj], node.Pos())
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					bind(name, node.Values[i])
				}
			}
		}
		return true
	})
	return state
}

// timeoutAssignedLater reports whether the variable or struct field that node
// is bound to gets a ReadHeaderTimeout or ReadTimeout assigned after the
// literal, as in:
//
//	srv := &http.Server{Addr: ":8080"}
//	srv.ReadHeaderTimeout = 5 * time.Second
//
//	a.srv = &http.Server{Addr: ":8080"}
//	a.srv.ReadHeaderTimeout = 5 * time.Second
func (r *slowloris) timeoutAssignedLater(node *ast.CompositeLit, ctx *gosec.Context) bool {
	state, ok := ctx.PassedValues[r.ID()].(*slowlorisFileState)
	if !ok {
		state = newSlowlorisFileState(ctx)
		ctx.PassedValues[r.ID()] = state
	}
	obj, ok := state.boundLits[node]
	if !ok {
		return false
	}
	for _, pos := range state.timeoutAssigns[obj] {
		if pos > node.End() {
			return true
		}
	}
	return false
}

func (r *slowloris) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.CompositeLit:
		actualType := ctx.Info.TypeOf(node.Type)
		if actualType != nil && actualType.String() == "net/http.Server" {
			if !containsReadHeaderTimeout(node, ctx) && !r.timeoutAssignedLater(node, ctx) {
				return ctx.NewIssue(node, r.ID(), r.What, r.Severity, r.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewSlowloris(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &slowloris{
		MetaData: issue.NewMetaData(id, "Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server", issue.Medium, issue.Low),
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}
