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

package gosec

import (
	"go/ast"
	"go/token"
	"go/types"
)

func resolveIdent(n *ast.Ident, c *Context) bool {
	if n.Obj == nil || n.Obj.Kind != ast.Var {
		return true
	}
	if node, ok := n.Obj.Decl.(ast.Node); ok {
		return TryResolve(node, c)
	}
	return false
}

func resolveValueSpec(n *ast.ValueSpec, c *Context) bool {
	if len(n.Values) == 0 {
		return false
	}
	for _, value := range n.Values {
		if !TryResolve(value, c) {
			return false
		}
	}
	return true
}

func resolveAssign(n *ast.AssignStmt, c *Context) bool {
	if len(n.Rhs) == 0 {
		return false
	}
	for _, arg := range n.Rhs {
		if !TryResolve(arg, c) {
			return false
		}
	}
	return true
}

func resolveCompLit(n *ast.CompositeLit, c *Context) bool {
	if len(n.Elts) == 0 {
		return false
	}
	for _, arg := range n.Elts {
		if !TryResolve(arg, c) {
			return false
		}
	}
	return true
}

func resolveBinExpr(n *ast.BinaryExpr, c *Context) bool {
	return (TryResolve(n.X, c) && TryResolve(n.Y, c))
}

func resolveCallExpr(node *ast.CallExpr, c *Context) bool {
	// A strings.Builder / bytes.Buffer .String() call resolves to a constant when
	// every value written to the receiver is itself a constant. This keeps rules
	// such as G202 consistent with their lenient handling of constant string
	// concatenation (e.g. building a value with +=) and avoids false positives
	// when a builder is used purely to assemble a constant string.
	if obj, ok := builderStringReceiver(node, c); ok {
		return builderWritesAreConst(obj, node, c)
	}
	// TODO(tkelsey): next step, full function resolution
	return false
}

// builderStringReceiver returns the receiver's object when node is a call to
// String() on a strings.Builder or bytes.Buffer value.
func builderStringReceiver(node *ast.CallExpr, c *Context) (types.Object, bool) {
	sel, ok := node.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" || len(node.Args) != 0 {
		return nil, false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || !isStringBuilderType(c.Info.TypeOf(ident)) {
		return nil, false
	}
	obj := c.Info.ObjectOf(ident)
	if obj == nil {
		return nil, false
	}
	// Only reason about local builders; a package-level one may be written to
	// in files we do not inspect here.
	if c.Pkg != nil && obj.Parent() == c.Pkg.Scope() {
		return nil, false
	}
	return obj, true
}

// isStringBuilderType reports whether t is strings.Builder or bytes.Buffer
// (or a pointer to either).
func isStringBuilderType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	switch obj.Pkg().Path() + "." + obj.Name() {
	case "strings.Builder", "bytes.Buffer":
		return true
	}
	return false
}

// builderWritesAreConst reports whether every value written to the builder
// referenced by obj is a constant. It is conservative: any usage of the builder
// that cannot be reasoned about (e.g. its address escaping to a function) makes
// it return false.
func builderWritesAreConst(obj types.Object, strCall *ast.CallExpr, c *Context) bool {
	file := ContainingFile(strCall, c)
	if file == nil {
		return false
	}

	allRefs := map[*ast.Ident]bool{}
	accounted := map[*ast.Ident]bool{}
	safe := true

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if c.Info.ObjectOf(node) == obj {
				allRefs[node] = true
			}
		case *ast.ValueSpec: // var b strings.Builder
			for _, name := range node.Names {
				if c.Info.ObjectOf(name) == obj {
					accounted[name] = true
				}
			}
		case *ast.AssignStmt:
			if node.Tok != token.DEFINE {
				return true
			}
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || c.Info.ObjectOf(id) != obj {
					continue
				}
				accounted[id] = true
				// Only an empty composite literal (strings.Builder{}) is a
				// known-empty starting point; anything else is opaque.
				if len(node.Rhs) != len(node.Lhs) || !isEmptyCompositeLit(node.Rhs[i]) {
					safe = false
				}
			}
		case *ast.CallExpr: // b.WriteString(...), b.String(), ...
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || c.Info.ObjectOf(recv) != obj {
				return true
			}
			accounted[recv] = true
			switch sel.Sel.Name {
			case "WriteString", "WriteByte", "WriteRune", "Write":
				for _, arg := range node.Args {
					if !TryResolve(arg, c) {
						safe = false
					}
				}
			case "String", "Len", "Cap", "Reset", "Grow":
				// read-only or adds no content
			default:
				safe = false
			}
		}
		return true
	})

	if !safe {
		return false
	}
	// Any reference we could not account for (e.g. &b passed to a function)
	// means the builder's contents are unknown.
	for id := range allRefs {
		if !accounted[id] {
			return false
		}
	}
	return true
}

// isEmptyCompositeLit reports whether e is an empty composite literal, optionally
// address-taken (e.g. strings.Builder{} or &strings.Builder{}).
func isEmptyCompositeLit(e ast.Expr) bool {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	cl, ok := e.(*ast.CompositeLit)
	return ok && len(cl.Elts) == 0
}

// TryResolve will attempt, given a subtree starting at some AST node, to resolve
// all values contained within to a known constant. It is used to check for any
// unknown values in compound expressions.
func TryResolve(n ast.Node, c *Context) bool {
	switch node := n.(type) {
	case *ast.BasicLit:
		return true
	case *ast.CompositeLit:
		return resolveCompLit(node, c)
	case *ast.Ident:
		return resolveIdent(node, c)
	case *ast.ValueSpec:
		return resolveValueSpec(node, c)
	case *ast.AssignStmt:
		return resolveAssign(node, c)
	case *ast.CallExpr:
		return resolveCallExpr(node, c)
	case *ast.BinaryExpr:
		return resolveBinExpr(node, c)
	case *ast.KeyValueExpr:
		return TryResolve(node.Key, c) && TryResolve(node.Value, c)
	case *ast.IndexExpr:
		return TryResolve(node.X, c)
	case *ast.SliceExpr:
		return TryResolve(node.X, c)
	}
	return false
}
