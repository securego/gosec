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

package core

import (
	"fmt"
	"go/ast"
	"reflect"
)

// SelectFunc is like an AST visitor, but has a richer interface. It
// is called with the current ast.Node being visitied and that nodes depth in
// the tree. The function can return true to continue traversing the tree, or
// false to end traversal here.
type SelectFunc func(ast.Node, int) bool

func walkIdentList(list []*ast.Ident, depth int, fun SelectFunc) {
	for _, x := range list {
		depthWalk(x, depth, fun)
	}
}

func walkExprList(list []ast.Expr, depth int, fun SelectFunc) {
	for _, x := range list {
		depthWalk(x, depth, fun)
	}
}

func walkStmtList(list []ast.Stmt, depth int, fun SelectFunc) {
	for _, x := range list {
		depthWalk(x, depth, fun)
	}
}

func walkDeclList(list []ast.Decl, depth int, fun SelectFunc) {
	for _, x := range list {
		depthWalk(x, depth, fun)
	}
}

func depthWalk(node ast.Node, depth int, fun SelectFunc) {
	if !fun(node, depth) {
		return
	}

	switch n := node.(type) {
	// Comments and fields
	case *ast.Comment:

	case *ast.CommentGroup:
		for _, c := range n.List {
			depthWalk(c, depth+1, fun)
		}

	case *ast.Field:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		walkIdentList(n.Names, depth+1, fun)
		depthWalk(n.Type, depth+1, fun)
		if n.Tag != nil {
			depthWalk(n.Tag, depth+1, fun)
		}
		if n.Comment != nil {
			depthWalk(n.Comment, depth+1, fun)
		}

	case *ast.FieldList:
		for _, f := range n.List {
			depthWalk(f, depth+1, fun)
		}

		// Expressions
	case *ast.BadExpr, *ast.Ident, *ast.BasicLit:

	case *ast.Ellipsis:
		if n.Elt != nil {
			depthWalk(n.Elt, depth+1, fun)
		}

	case *ast.FuncLit:
		depthWalk(n.Type, depth+1, fun)
		depthWalk(n.Body, depth+1, fun)

	case *ast.CompositeLit:
		if n.Type != nil {
			depthWalk(n.Type, depth+1, fun)
		}
		walkExprList(n.Elts, depth+1, fun)

	case *ast.ParenExpr:
		depthWalk(n.X, depth+1, fun)

	case *ast.SelectorExpr:
		depthWalk(n.X, depth+1, fun)
		depthWalk(n.Sel, depth+1, fun)

	case *ast.IndexExpr:
		depthWalk(n.X, depth+1, fun)
		depthWalk(n.Index, depth+1, fun)

	case *ast.SliceExpr:
		depthWalk(n.X, depth+1, fun)
		if n.Low != nil {
			depthWalk(n.Low, depth+1, fun)
		}
		if n.High != nil {
			depthWalk(n.High, depth+1, fun)
		}
		if n.Max != nil {
			depthWalk(n.Max, depth+1, fun)
		}

	case *ast.TypeAssertExpr:
		depthWalk(n.X, depth+1, fun)
		if n.Type != nil {
			depthWalk(n.Type, depth+1, fun)
		}

	case *ast.CallExpr:
		depthWalk(n.Fun, depth+1, fun)
		walkExprList(n.Args, depth+1, fun)

	case *ast.StarExpr:
		depthWalk(n.X, depth+1, fun)

	case *ast.UnaryExpr:
		depthWalk(n.X, depth+1, fun)

	case *ast.BinaryExpr:
		depthWalk(n.X, depth+1, fun)
		depthWalk(n.Y, depth+1, fun)

	case *ast.KeyValueExpr:
		depthWalk(n.Key, depth+1, fun)
		depthWalk(n.Value, depth+1, fun)

	// Types
	case *ast.ArrayType:
		if n.Len != nil {
			depthWalk(n.Len, depth+1, fun)
		}
		depthWalk(n.Elt, depth+1, fun)

	case *ast.StructType:
		depthWalk(n.Fields, depth+1, fun)

	case *ast.FuncType:
		if n.Params != nil {
			depthWalk(n.Params, depth+1, fun)
		}
		if n.Results != nil {
			depthWalk(n.Results, depth+1, fun)
		}

	case *ast.InterfaceType:
		depthWalk(n.Methods, depth+1, fun)

	case *ast.MapType:
		depthWalk(n.Key, depth+1, fun)
		depthWalk(n.Value, depth+1, fun)

	case *ast.ChanType:
		depthWalk(n.Value, depth+1, fun)

	// Statements
	case *ast.BadStmt:

	case *ast.DeclStmt:
		depthWalk(n.Decl, depth+1, fun)

	case *ast.EmptyStmt:

	case *ast.LabeledStmt:
		depthWalk(n.Label, depth+1, fun)
		depthWalk(n.Stmt, depth+1, fun)

	case *ast.ExprStmt:
		depthWalk(n.X, depth+1, fun)

	case *ast.SendStmt:
		depthWalk(n.Chan, depth+1, fun)
		depthWalk(n.Value, depth+1, fun)

	case *ast.IncDecStmt:
		depthWalk(n.X, depth+1, fun)

	case *ast.AssignStmt:
		walkExprList(n.Lhs, depth+1, fun)
		walkExprList(n.Rhs, depth+1, fun)

	case *ast.GoStmt:
		depthWalk(n.Call, depth+1, fun)

	case *ast.DeferStmt:
		depthWalk(n.Call, depth+1, fun)

	case *ast.ReturnStmt:
		walkExprList(n.Results, depth+1, fun)

	case *ast.BranchStmt:
		if n.Label != nil {
			depthWalk(n.Label, depth+1, fun)
		}

	case *ast.BlockStmt:
		walkStmtList(n.List, depth+1, fun)

	case *ast.IfStmt:
		if n.Init != nil {
			depthWalk(n.Init, depth+1, fun)
		}
		depthWalk(n.Cond, depth+1, fun)
		depthWalk(n.Body, depth+1, fun)
		if n.Else != nil {
			depthWalk(n.Else, depth+1, fun)
		}

	case *ast.CaseClause:
		walkExprList(n.List, depth+1, fun)
		walkStmtList(n.Body, depth+1, fun)

	case *ast.SwitchStmt:
		if n.Init != nil {
			depthWalk(n.Init, depth+1, fun)
		}
		if n.Tag != nil {
			depthWalk(n.Tag, depth+1, fun)
		}
		depthWalk(n.Body, depth+1, fun)

	case *ast.TypeSwitchStmt:
		if n.Init != nil {
			depthWalk(n.Init, depth+1, fun)
		}
		depthWalk(n.Assign, depth+1, fun)
		depthWalk(n.Body, depth+1, fun)

	case *ast.CommClause:
		if n.Comm != nil {
			depthWalk(n.Comm, depth+1, fun)
		}
		walkStmtList(n.Body, depth+1, fun)

	case *ast.SelectStmt:
		depthWalk(n.Body, depth+1, fun)

	case *ast.ForStmt:
		if n.Init != nil {
			depthWalk(n.Init, depth+1, fun)
		}
		if n.Cond != nil {
			depthWalk(n.Cond, depth+1, fun)
		}
		if n.Post != nil {
			depthWalk(n.Post, depth+1, fun)
		}
		depthWalk(n.Body, depth+1, fun)

	case *ast.RangeStmt:
		if n.Key != nil {
			depthWalk(n.Key, depth+1, fun)
		}
		if n.Value != nil {
			depthWalk(n.Value, depth+1, fun)
		}
		depthWalk(n.X, depth+1, fun)
		depthWalk(n.Body, depth+1, fun)

	// Declarations
	case *ast.ImportSpec:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		if n.Name != nil {
			depthWalk(n.Name, depth+1, fun)
		}
		depthWalk(n.Path, depth+1, fun)
		if n.Comment != nil {
			depthWalk(n.Comment, depth+1, fun)
		}

	case *ast.ValueSpec:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		walkIdentList(n.Names, depth+1, fun)
		if n.Type != nil {
			depthWalk(n.Type, depth+1, fun)
		}
		walkExprList(n.Values, depth+1, fun)
		if n.Comment != nil {
			depthWalk(n.Comment, depth+1, fun)
		}

	case *ast.TypeSpec:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		depthWalk(n.Name, depth+1, fun)
		depthWalk(n.Type, depth+1, fun)
		if n.Comment != nil {
			depthWalk(n.Comment, depth+1, fun)
		}

	case *ast.BadDecl:

	case *ast.GenDecl:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		for _, s := range n.Specs {
			depthWalk(s, depth+1, fun)
		}

	case *ast.FuncDecl:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		if n.Recv != nil {
			depthWalk(n.Recv, depth+1, fun)
		}
		depthWalk(n.Name, depth+1, fun)
		depthWalk(n.Type, depth+1, fun)
		if n.Body != nil {
			depthWalk(n.Body, depth+1, fun)
		}

	// Files and packages
	case *ast.File:
		if n.Doc != nil {
			depthWalk(n.Doc, depth+1, fun)
		}
		depthWalk(n.Name, depth+1, fun)
		walkDeclList(n.Decls, depth+1, fun)
		// don't walk n.Comments - they have been
		// visited already through the individual
		// nodes

	case *ast.Package:
		for _, f := range n.Files {
			depthWalk(f, depth+1, fun)
		}

	default:
		panic(fmt.Sprintf("gas.depthWalk: unexpected node type %T", n))
	}
}

type Selector interface {
	Final(ast.Node)
	Partial(ast.Node) bool
}

func Select(s Selector, n ast.Node, bits ...reflect.Type) {
	fun := func(n ast.Node, d int) bool {
		if d < len(bits) && reflect.TypeOf(n) == bits[d] {
			if d == len(bits)-1 {
				s.Final(n)
				return false
			} else if s.Partial(n) {
				return true
			}
		}
		return false
	}
	depthWalk(n, 0, fun)
}

// SimpleSelect will try to match a path through a sub-tree starting at a given AST node.
// The type of each node in the path at a given depth must match its entry in list of
// node types given.
func SimpleSelect(n ast.Node, bits ...reflect.Type) ast.Node {
	var found ast.Node
	fun := func(n ast.Node, d int) bool {
		if found != nil {
			return false // short cut logic if we have found a match
		}

		if d < len(bits) && reflect.TypeOf(n) == bits[d] {
			if d == len(bits)-1 {
				found = n
				return false
			}
			return true
		}
		return false
	}

	depthWalk(n, 0, fun)
	return found
}
