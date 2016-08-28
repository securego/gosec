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
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// helpfull "canned" matching routines ----------------------------------------

func selectName(n ast.Node, s reflect.Type) (string, bool) {
	t := reflect.TypeOf(&ast.SelectorExpr{})
	if node, ok := SimpleSelect(n, s, t).(*ast.SelectorExpr); ok {
		t = reflect.TypeOf(&ast.Ident{})
		if ident, ok := SimpleSelect(node.X, t).(*ast.Ident); ok {
			return strings.Join([]string{ident.Name, node.Sel.Name}, "."), ok
		}
	}
	return "", false
}

// MatchCall will match an ast.CallNode if its method name obays the given regex.
func MatchCall(n ast.Node, r *regexp.Regexp) *ast.CallExpr {
	t := reflect.TypeOf(&ast.CallExpr{})
	if name, ok := selectName(n, t); ok && r.MatchString(name) {
		return n.(*ast.CallExpr)
	}
	return nil
}

// MatcMatchCompLit hCall will match an ast.CompositeLit if its string value obays the given regex.
func MatchCompLit(n ast.Node, r *regexp.Regexp) *ast.CompositeLit {
	t := reflect.TypeOf(&ast.CompositeLit{})
	if name, ok := selectName(n, t); ok && r.MatchString(name) {
		return n.(*ast.CompositeLit)
	}
	return nil
}

// GetInt will read and return an integer value from an ast.BasicLit
func GetInt(n ast.Node) (int64, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.INT {
		return strconv.ParseInt(node.Value, 0, 64)
	}
	return 0, fmt.Errorf("Unexpected AST node type: %T", n)
}

// GetInt will read and return a float value from an ast.BasicLit
func GetFloat(n ast.Node) (float64, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.FLOAT {
		return strconv.ParseFloat(node.Value, 64)
	}
	return 0.0, fmt.Errorf("Unexpected AST node type: %T", n)
}

// GetInt will read and return a char value from an ast.BasicLit
func GetChar(n ast.Node) (byte, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.CHAR {
		return node.Value[0], nil
	}
	return 0, fmt.Errorf("Unexpected AST node type: %T", n)
}

// GetInt will read and return a string value from an ast.BasicLit
func GetString(n ast.Node) (string, error) {
	if node, ok := n.(*ast.BasicLit); ok && node.Kind == token.STRING {
		return strconv.Unquote(node.Value)
	}
	return "", fmt.Errorf("Unexpected AST node type: %T", n)
}
