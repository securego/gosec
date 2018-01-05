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

	"github.com/GoASTScanner/gas"
)

type sqlStatement struct {
	gas.MetaData
	pattern *regexp.Regexp
}

type sqlStrConcat struct {
	sqlStatement
}

// see if we can figure out what it is
func (s *sqlStrConcat) checkObject(n *ast.Ident) bool {
	if n.Obj != nil {
		return n.Obj.Kind != ast.Var && n.Obj.Kind != ast.Fun
	}
	return false
}

// Look for "SELECT * FROM table WHERE " + " ' OR 1=1"
func (s *sqlStrConcat) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
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

// NewSQLStrConcat looks for cases where we are building SQL strings via concatenation
func NewSQLStrConcat(conf gas.Config) (gas.Rule, []ast.Node) {
	return &sqlStrConcat{
		sqlStatement: sqlStatement{
			pattern: regexp.MustCompile(`(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) `),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string concatenation",
			},
		},
	}, []ast.Node{(*ast.BinaryExpr)(nil)}
}

type sqlStrFormat struct {
	sqlStatement
	calls gas.CallList
}

// Looks for "fmt.Sprintf("SELECT * FROM foo where '%s', userInput)"
func (s *sqlStrFormat) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {

	// TODO(gm) improve confidence if database/sql is being used
	if node := s.calls.ContainsCallExpr(n, c); node != nil {
		if arg, e := gas.GetString(node.Args[0]); s.pattern.MatchString(arg) && e == nil {
			return gas.NewIssue(c, n, s.What, s.Severity, s.Confidence), nil
		}
	}
	return nil, nil
}

// NewSQLStrFormat looks for cases where we're building SQL query strings using format strings
func NewSQLStrFormat(conf gas.Config) (gas.Rule, []ast.Node) {
	rule := &sqlStrFormat{
		calls: gas.NewCallList(),
		sqlStatement: sqlStatement{
			pattern: regexp.MustCompile("(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) "),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string formatting",
			},
		},
	}
	rule.calls.AddAll("fmt", "Sprint", "Sprintf", "Sprintln")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
