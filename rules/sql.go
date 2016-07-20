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
	gas "github.com/HewlettPackard/gas/core"
	"go/ast"
	"reflect"
	"regexp"
)

type SqlStatement struct {
	gas.MetaData
	pattern *regexp.Regexp
}

type SqlStrConcat struct {
	SqlStatement
}

// Look for "SELECT * FROM table WHERE " + " ' OR 1=1"
func (s *SqlStrConcat) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	a := reflect.TypeOf(&ast.BinaryExpr{})
	b := reflect.TypeOf(&ast.BasicLit{})
	if node := gas.SimpleSelect(n, a, b); node != nil {
		if str, _ := gas.GetString(node); s.pattern.MatchString(str) {
			return gas.NewIssue(c, n, s.What, s.Severity, s.Confidence), nil
		}
	}
	return nil, nil
}

func NewSqlStrConcat() (r gas.Rule, n ast.Node) {
	r = &SqlStrConcat{
		SqlStatement: SqlStatement{
			pattern: regexp.MustCompile("(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) "),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string concatenation",
			},
		},
	}
	n = (*ast.BinaryExpr)(nil)
	return
}

type SqlStrFormat struct {
	SqlStatement
	call *regexp.Regexp
}

// Looks for "fmt.Sprintf("SELECT * FROM foo where '%s', userInput)"
func (s *SqlStrFormat) Match(n ast.Node, c *gas.Context) (gi *gas.Issue, err error) {
	if node := gas.MatchCall(n, s.call); node != nil {
		if arg, _ := gas.GetString(node.Args[0]); s.pattern.MatchString(arg) {
			return gas.NewIssue(c, n, s.What, s.Severity, s.Confidence), nil
		}
	}
	return nil, nil
}

func NewSqlStrFormat() (r gas.Rule, n ast.Node) {
	r = &SqlStrFormat{
		call: regexp.MustCompile("^fmt.Sprintf$"),
		SqlStatement: SqlStatement{
			pattern: regexp.MustCompile("(?)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) "),
			MetaData: gas.MetaData{
				Severity:   gas.Medium,
				Confidence: gas.High,
				What:       "SQL string formatting",
			},
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}
