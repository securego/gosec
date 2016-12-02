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
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type SqlStatement struct {
	gas.MetaData
	pattern *regexp.Regexp
}

type SqlStrConcat struct {
	SqlStatement
}

// see if we can figure out what it is
func (s *SqlStrConcat) checkObject(n *ast.Ident) bool {
	if n.Obj != nil {
		return n.Obj.Kind != ast.Var && n.Obj.Kind != ast.Fun
	}
	return false
}

// Look for "SELECT * FROM table WHERE " + " ' OR 1=1"
func (s *SqlStrConcat) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node, ok := n.(*ast.BinaryExpr); ok {
		if start, ok := node.X.(*ast.BasicLit); ok {
			if str, e := gas.GetString(start); s.pattern.MatchString(str) && e == nil {
				if _, ok := node.Y.(*ast.BasicLit); ok {
					return nil, nil // string cat OK
				}
				if second, ok := node.Y.(*ast.Ident); ok && s.checkObject(second) {
					return nil, nil
				}
				return gas.NewIssue(c, n, s.What, s.Severity, s.Confidence), nil
			}
		}
	}
	return nil, nil
}

func NewSqlStrConcat(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &SqlStrConcat{
		SqlStatement: SqlStatement{
			pattern: regexp.MustCompile(`(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) `),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string concatenation",
			},
		},
	}, []ast.Node{(*ast.BinaryExpr)(nil)}
}

type SqlStrFormat struct {
	SqlStatement
	call *regexp.Regexp
}

// Looks for "fmt.Sprintf("SELECT * FROM foo where '%s', userInput)"
func (s *SqlStrFormat) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node := gas.MatchCall(n, s.call); node != nil {
		if arg, e := gas.GetString(node.Args[0]); s.pattern.MatchString(arg) && e == nil {
			return gas.NewIssue(c, n, s.What, s.Severity, s.Confidence), nil
		}
	}
	return nil, nil
}

func NewSqlStrFormat(conf map[string]interface{}) (gas.Rule, []ast.Node) {
	return &SqlStrFormat{
		call: regexp.MustCompile(`^fmt\.Sprintf$`),
		SqlStatement: SqlStatement{
			pattern: regexp.MustCompile("(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) "),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string formatting",
			},
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
