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
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sqlStatement struct {
	issue.MetaData
	gosec.CallList

	// Contains a list of patterns which must all match for the rule to match.
	patterns []*regexp.Regexp
}

var sqlCallIdents = map[string]map[string]int{
	"*database/sql.Conn": {
		"ExecContext":     1,
		"QueryContext":    1,
		"QueryRowContext": 1,
		"PrepareContext":  1,
	},
	"*database/sql.DB": {
		"Exec":            0,
		"ExecContext":     1,
		"Query":           0,
		"QueryContext":    1,
		"QueryRow":        0,
		"QueryRowContext": 1,
		"Prepare":         0,
		"PrepareContext":  1,
	},
	"*database/sql.Tx": {
		"Exec":            0,
		"ExecContext":     1,
		"Query":           0,
		"QueryContext":    1,
		"QueryRow":        0,
		"QueryRowContext": 1,
		"Prepare":         0,
		"PrepareContext":  1,
	},
}

// findQueryArg locates the argument taking raw SQL.
func findQueryArg(call *ast.CallExpr, ctx *gosec.Context) (ast.Expr, error) {
	typeName, fnName, err := gosec.GetCallInfo(call, ctx)
	if err != nil {
		return nil, err
	}

	if methods, ok := sqlCallIdents[typeName]; ok {
		if i, ok := methods[fnName]; ok && i < len(call.Args) {
			return call.Args[i], nil
		}
	}

	return nil, fmt.Errorf("SQL argument index not found for %s.%s", typeName, fnName)
}

func (s *sqlStatement) ID() string {
	return s.MetaData.ID
}

// MatchPatterns checks if the string matches all required SQL patterns.
func (s *sqlStatement) MatchPatterns(str string) bool {
	for _, pattern := range s.patterns {
		if !pattern.MatchString(str) {
			return false
		}
	}
	return true
}

type sqlStrConcat struct {
	sqlStatement
}

func (s *sqlStrConcat) ID() string {
	return s.MetaData.ID
}

// findInjectionInBranch walks through a set of expressions and returns the first
// binary expression containing a potential injection (non-constant operand).
// This method assumes the branch already contains SQL syntax.
func (s *sqlStrConcat) findInjectionInBranch(ctx *gosec.Context, branch []ast.Expr) *ast.BinaryExpr {
	for _, node := range branch {
		be, ok := node.(*ast.BinaryExpr)
		if !ok {
			continue
		}

		for _, op := range gosec.GetBinaryExprOperands(be) {
			if gosec.TryResolve(op, ctx) {
				continue
			}
			return be
		}
	}
	return nil
}

// checkQuery verifies if the query parameter involves risky string concatenation.
func (s *sqlStrConcat) checkQuery(call *ast.CallExpr, ctx *gosec.Context) (*issue.Issue, error) {
	query, err := findQueryArg(call, ctx)
	if err != nil {
		return nil, err
	}

	// Direct binary concatenation (e.g., "SELECT ..." + tainted)
	if be, ok := query.(*ast.BinaryExpr); ok {
		operands := gosec.GetBinaryExprOperands(be)
		if start, ok := operands[0].(*ast.BasicLit); ok {
			if str, e := gosec.GetString(start); e == nil && s.MatchPatterns(str) {
				for _, op := range operands[1:] {
					if gosec.TryResolve(op, ctx) {
						continue
					}
					return ctx.NewIssue(be, s.ID(), s.What, s.Severity, s.Confidence), nil
				}
			}
		}
	}

	// Identifier-based query (e.g., var query = ...; query += ...; query = query + ...)
	id, ok := query.(*ast.Ident)
	if !ok {
		return nil, nil
	}

	// Confirm the identifier resolves to a string containing SQL patterns
	if !slices.ContainsFunc(gosec.GetIdentStringValuesRecursive(id), s.MatchPatterns) {
		return nil, nil
	}

	// Check initial declaration for direct risky concatenation
	if id.Obj != nil {
		switch decl := id.Obj.Decl.(type) {
		case *ast.AssignStmt:
			if injection := s.findInjectionInBranch(ctx, decl.Rhs); injection != nil {
				return ctx.NewIssue(injection, s.ID(), s.What, s.Severity, s.Confidence), nil
			}
		case *ast.ValueSpec:
			if injection := s.findInjectionInBranch(ctx, decl.Values); injection != nil {
				return ctx.NewIssue(injection, s.ID(), s.What, s.Severity, s.Confidence), nil
			}
		}
	} else {
		// Unresolved identifier - nothing more to check
		return nil, nil
	}

	// Check for risky mutations (query += tainted or query = query + tainted)
	callFile := gosec.ContainingFile(call, ctx)
	if callFile == nil {
		return nil, nil
	}

	// Determine if the variable is package-level
	isPkgLevel := false
	if ctx.Info != nil {
		if obj := ctx.Info.ObjectOf(id); obj != nil {
			if tv, ok := obj.(*types.Var); ok && ctx.Pkg != nil && ctx.Pkg.Scope() != nil {
				isPkgLevel = tv.Parent() == ctx.Pkg.Scope()
			}
		}
	}

	var filesToSearch []*ast.File
	if isPkgLevel {
		filesToSearch = ctx.PkgFiles // all files (rare case)
	} else {
		filesToSearch = []*ast.File{callFile} // common case: local var
	}

	var found *ast.AssignStmt
	for _, f := range filesToSearch {
		ast.Inspect(f, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			lIdent, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || lIdent.Obj != id.Obj {
				return true
			}

			var appended ast.Expr
			switch assign.Tok {
			case token.ADD_ASSIGN:
				appended = assign.Rhs[0]
			case token.ASSIGN:
				be, ok := assign.Rhs[0].(*ast.BinaryExpr)
				if !ok || be.Op != token.ADD {
					return true
				}
				left, ok := be.X.(*ast.Ident)
				if !ok || left.Obj != id.Obj {
					return true
				}

				appended = be.Y
			default:
				return true
			}

			if !gosec.TryResolve(appended, ctx) {
				found = assign
				return false
			}
			return true
		})
		if found != nil {
			return ctx.NewIssue(found, s.ID(), s.What, s.Severity, s.Confidence), nil
		}
	}

	return nil, nil
}

// Match looks for SQL execution calls and checks for concatenation issues.
func (s *sqlStrConcat) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range stmt.Rhs {
			if call, ok := expr.(*ast.CallExpr); ok && s.ContainsCallExpr(expr, ctx) != nil {
				return s.checkQuery(call, ctx)
			}
		}
	case *ast.ExprStmt:
		if call, ok := stmt.X.(*ast.CallExpr); ok && s.ContainsCallExpr(call, ctx) != nil {
			return s.checkQuery(call, ctx)
		}
	}
	return nil, nil
}

// NewSQLStrConcat creates a rule for detecting SQL string concatenation.
func NewSQLStrConcat(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &sqlStrConcat{
		sqlStatement: sqlStatement{
			patterns: []*regexp.Regexp{
				regexp.MustCompile("(?i)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE)( |\n|\r|\t)"),
			},
			MetaData: issue.MetaData{
				ID:         id,
				Severity:   issue.Medium,
				Confidence: issue.High,
				What:       "SQL string concatenation",
			},
			CallList: gosec.NewCallList(),
		},
	}

	for typ, methods := range sqlCallIdents {
		for method := range methods {
			rule.Add(typ, method)
		}
	}
	return rule, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ExprStmt)(nil)}
}

type sqlStrFormat struct {
	gosec.CallList
	sqlStatement
	fmtCalls      gosec.CallList
	noIssue       gosec.CallList
	noIssueQuoted gosec.CallList
}

// checkQuery verifies if the query parameter involves risky formatting.
func (s *sqlStrFormat) checkQuery(call *ast.CallExpr, ctx *gosec.Context) (*issue.Issue, error) {
	query, err := findQueryArg(call, ctx)
	if err != nil {
		return nil, err
	}

	if ident, ok := query.(*ast.Ident); ok && ident.Obj != nil {
		if assign, ok := ident.Obj.Decl.(*ast.AssignStmt); ok {
			for _, expr := range assign.Rhs {
				if issue := s.checkFormatting(expr, ctx); issue != nil {
					return issue, nil
				}
			}
		}
	}

	return nil, nil
}

// checkFormatting checks if a formatting call builds a risky SQL query.
func (s *sqlStrFormat) checkFormatting(n ast.Node, ctx *gosec.Context) *issue.Issue {
	// argIndex changes the function argument which gets matched to the regex
	argIndex := 0
	if node := s.fmtCalls.ContainsPkgCallExpr(n, ctx, false); node != nil {
		// if the function is fmt.Fprintf, search for SQL statement in Args[1] instead
		if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fprintf" {
			// if os.Stderr or os.Stdout is in Arg[0], mark as no issue
			if arg, ok := node.Args[0].(*ast.SelectorExpr); ok {
				if ident, ok := arg.X.(*ast.Ident); ok && s.noIssue.Contains(ident.Name, arg.Sel.Name) {
					return nil
				}
			}
			// the function is Fprintf so set argIndex = 1
			argIndex = 1
		}

		// no formatter
		if len(node.Args) == 0 {
			return nil
		}

		formatter, ok := gosec.ConcatString(node.Args[argIndex], ctx)
		if !ok || formatter == "" {
			return nil
		}

		// If all formatter args are quoted or constant, then the SQL construction is safe
		if argIndex+1 < len(node.Args) {
			allSafe := true
			for _, arg := range node.Args[argIndex+1:] {
				if s.noIssueQuoted.ContainsPkgCallExpr(arg, ctx, true) == nil && !gosec.TryResolve(arg, ctx) {
					allSafe = false
					break
				}
			}
			if allSafe {
				return nil
			}
		}

		if s.MatchPatterns(formatter) {
			return ctx.NewIssue(n, s.ID(), s.What, s.Severity, s.Confidence)
		}
	}
	return nil
}

// Match looks for SQL calls involving formatted strings.
func (s *sqlStrFormat) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		for _, expr := range stmt.Rhs {
			if call, ok := expr.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if sqlCall, ok := sel.X.(*ast.CallExpr); ok && s.ContainsCallExpr(sqlCall, ctx) != nil {
						return s.checkQuery(sqlCall, ctx)
					}
				}
				if s.ContainsCallExpr(expr, ctx) != nil {
					return s.checkQuery(call, ctx)
				}
			}
		}
	case *ast.ExprStmt:
		if call, ok := stmt.X.(*ast.CallExpr); ok && s.ContainsCallExpr(call, ctx) != nil {
			return s.checkQuery(call, ctx)
		}
	}
	return nil, nil
}

// NewSQLStrFormat creates a rule for detecting SQL string formatting.
func NewSQLStrFormat(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &sqlStrFormat{
		CallList:      gosec.NewCallList(),
		fmtCalls:      gosec.NewCallList(),
		noIssue:       gosec.NewCallList(),
		noIssueQuoted: gosec.NewCallList(),
		sqlStatement: sqlStatement{
			patterns: []*regexp.Regexp{
				regexp.MustCompile("(?i)(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE)( |\n|\r|\t)"),
				regexp.MustCompile("%[^bdoxXfFp]"),
			},
			MetaData: issue.MetaData{
				ID:         id,
				Severity:   issue.Medium,
				Confidence: issue.High,
				What:       "SQL string formatting",
			},
		},
	}
	for typ, methods := range sqlCallIdents {
		for method := range methods {
			rule.Add(typ, method)
		}
	}
	rule.fmtCalls.AddAll("fmt", "Sprint", "Sprintf", "Sprintln", "Fprintf")
	rule.noIssue.AddAll("os", "Stdout", "Stderr")
	rule.noIssueQuoted.Add("github.com/lib/pq", "QuoteIdentifier")
	return rule, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ExprStmt)(nil)}
}
