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
	"go/types"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type readfile struct {
	issue.MetaData
	gosec.CallList
	pathJoin gosec.CallList
	clean    gosec.CallList
	// cleanedVar maps the declaration node of an identifier to the Clean() call node
	cleanedVar map[any]ast.Node
	// joinedVar maps the declaration node of an identifier to the Join() call node
	joinedVar map[any]ast.Node
}

// ID returns the identifier for this rule
func (r *readfile) ID() string {
	return r.MetaData.ID
}

// isJoinFunc checks if there is a filepath.Join or other join function
func (r *readfile) isJoinFunc(n ast.Node, c *gosec.Context) bool {
	if call := r.pathJoin.ContainsPkgCallExpr(n, c, false); call != nil {
		for _, arg := range call.Args {
			// edge case: check if one of the args is a BinaryExpr
			if binExp, ok := arg.(*ast.BinaryExpr); ok {
				// iterate and resolve all found identities from the BinaryExpr
				if _, ok := gosec.FindVarIdentities(binExp, c); ok {
					return true
				}
			}

			// try and resolve identity
			if ident, ok := arg.(*ast.Ident); ok {
				obj := c.Info.ObjectOf(ident)
				if _, ok := obj.(*types.Var); ok && !gosec.TryResolve(ident, c) {
					return true
				}
			}
		}
	}
	return false
}

// isFilepathClean checks if there is a filepath.Clean for given variable
func (r *readfile) isFilepathClean(n *ast.Ident, c *gosec.Context) bool {
	// quick lookup: was this var's declaration recorded as a Clean() call?
	if _, ok := r.cleanedVar[n.Obj.Decl]; ok {
		return true
	}
	if n.Obj.Kind != ast.Var {
		return false
	}
	if node, ok := n.Obj.Decl.(*ast.AssignStmt); ok {
		if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
			if clean := r.clean.ContainsPkgCallExpr(call, c, false); clean != nil {
				return true
			}
		}
	}
	return false
}

// trackFilepathClean tracks back the declaration of variable from filepath.Clean argument
func (r *readfile) trackFilepathClean(n ast.Node) {
	if clean, ok := n.(*ast.CallExpr); ok && len(clean.Args) > 0 {
		if ident, ok := clean.Args[0].(*ast.Ident); ok {
			// ident.Obj may be nil if the referenced declaration is in another file. It also may be incorrect.
			// if it is nil, do not follow it.
			if ident.Obj != nil {
				r.cleanedVar[ident.Obj.Decl] = n
			}
		}
	}
}

// trackJoinAssignStmt tracks assignments where RHS is a Join(...) call and LHS is an identifier
func (r *readfile) trackJoinAssignStmt(node *ast.AssignStmt, c *gosec.Context) {
	if len(node.Rhs) == 0 {
		return
	}
	if call, ok := node.Rhs[0].(*ast.CallExpr); ok {
		if r.pathJoin.ContainsPkgCallExpr(call, c, false) != nil {
			// LHS must be an identifier (simple case)
			if len(node.Lhs) > 0 {
				if ident, ok := node.Lhs[0].(*ast.Ident); ok && ident.Obj != nil {
					r.joinedVar[ident.Obj.Decl] = call
				}
			}
		}
	}
}

// osRootSuggestion returns an Autofix suggesting the use of os.Root where supported
// to constrain file access under a fixed directory and mitigate traversal risks.
func (r *readfile) osRootSuggestion() string {
	major, minor, _ := gosec.GoVersion()
	if major == 1 && minor >= 24 {
		return "Consider using os.Root to scope file access under a fixed root (Go >=1.24). Prefer root.Open/root.Stat over os.Open/os.Stat to prevent directory traversal."
	}
	return ""
}

// isSafeJoin checks if path is baseDir + filepath.Clean(fn) joined.
// improvements over earlier naive version:
// - allow baseDir as a BasicLit or as an identifier that resolves to a string constant
// - accept Clean(...) being either a CallExpr or an identifier previously recorded as Clean result
func (r *readfile) isSafeJoin(call *ast.CallExpr, c *gosec.Context) bool {
	join := r.pathJoin.ContainsPkgCallExpr(call, c, false)
	if join == nil {
		return false
	}

	// We expect join.Args to include a baseDir-like arg and a cleaned path arg.
	var foundBaseDir bool
	var foundCleanArg bool

	for _, arg := range join.Args {
		switch a := arg.(type) {
		case *ast.BasicLit:
			// literal string or similar — treat as possible baseDir
			foundBaseDir = true
		case *ast.Ident:
			// If ident is resolvable to a constant string (TryResolve true), treat as baseDir.
			// Or if ident refers to a variable that was itself assigned from a constant BasicLit,
			// it's considered safe as baseDir.
			if gosec.TryResolve(a, c) {
				foundBaseDir = true
			} else {
				// It might be a cleaned variable: e.g. cleanPath := filepath.Clean(fn)
				if r.isFilepathClean(a, c) {
					foundCleanArg = true
				}
			}
		case *ast.CallExpr:
			// If an argument is a Clean() call directly, mark clean arg found.
			if r.clean.ContainsPkgCallExpr(a, c, false) != nil {
				foundCleanArg = true
			}
		default:
			// ignore other types
		}
	}

	return foundBaseDir && foundCleanArg
}

func (r *readfile) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// Track filepath.Clean usages so identifiers assigned from Clean() are known.
	if node := r.clean.ContainsPkgCallExpr(n, c, false); node != nil {
		r.trackFilepathClean(n)
		return nil, nil
	}

	// Track Join assignments if we see an AssignStmt whose RHS is a Join call.
	if assign, ok := n.(*ast.AssignStmt); ok {
		// track join result assigned to a variable, e.g., fullPath := filepath.Join(baseDir, cleanPath)
		r.trackJoinAssignStmt(assign, c)
		// also track Clean assignment if present on RHS
		if len(assign.Rhs) > 0 {
			if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
				if r.clean.ContainsPkgCallExpr(call, c, false) != nil {
					r.trackFilepathClean(call)
				}
			}
		}
		// continue, don't return here — other checks may apply
	}

	// Now check for file-reading calls (os.Open, os.OpenFile, ioutil.ReadFile etc.)
	if node := r.ContainsPkgCallExpr(n, c, false); node != nil {
		if len(node.Args) == 0 {
			return nil, nil
		}
		arg := node.Args[0]

		// If argument is a call expression, check for Join/Clean patterns.
		if callExpr, ok := arg.(*ast.CallExpr); ok {
			// If this call matches a safe Join(baseDir, Clean(...)) pattern, treat as safe.
			if r.isSafeJoin(callExpr, c) {
				// safe pattern detected; do not raise an issue
				return nil, nil
			}
			// If the argument is a Join call but not safe per above, flag it (as before)
			if r.isJoinFunc(callExpr, c) {
				iss := c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence)
				if s := r.osRootSuggestion(); s != "" {
					iss.Autofix = s
				}
				return iss, nil
			}
		}

		// If arg is an identifier that was assigned from a Join(...) call, check that recorded Join call.
		if ident, ok := arg.(*ast.Ident); ok {
			if ident.Obj != nil {
				if joinCall, ok := r.joinedVar[ident.Obj.Decl]; ok {
					// If the identifier itself was later cleaned, treat as safe regardless of original Join args
					if r.isFilepathClean(ident, c) {
						return nil, nil
					}
					// joinCall is a *ast.CallExpr; check if that join is a safe join
					if jc, ok := joinCall.(*ast.CallExpr); ok {
						if r.isSafeJoin(jc, c) {
							return nil, nil
						}
						// join exists but is not safe: flag it
						iss := c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence)
						if s := r.osRootSuggestion(); s != "" {
							iss.Autofix = s
						}
						return iss, nil
					}
				}
			}
		}

		// handles binary string concatenation eg. ioutil.Readfile("/tmp/" + file + "/blob")
		if binExp, ok := arg.(*ast.BinaryExpr); ok {
			// resolve all found identities from the BinaryExpr
			if _, ok := gosec.FindVarIdentities(binExp, c); ok {
				iss := c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence)
				if s := r.osRootSuggestion(); s != "" {
					iss.Autofix = s
				}
				return iss, nil
			}
		}

		// if it's a plain identifier, and not resolved and not cleaned, flag it
		if ident, ok := arg.(*ast.Ident); ok {
			obj := c.Info.ObjectOf(ident)
			if _, ok := obj.(*types.Var); ok &&
				!gosec.TryResolve(ident, c) &&
				!r.isFilepathClean(ident, c) {
				iss := c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence)
				if s := r.osRootSuggestion(); s != "" {
					iss.Autofix = s
				}
				return iss, nil
			}
		}
	}
	return nil, nil
}

// NewReadFile detects cases where we read files
func NewReadFile(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &readfile{
		pathJoin: gosec.NewCallList(),
		clean:    gosec.NewCallList(),
		CallList: gosec.NewCallList(),
		MetaData: issue.MetaData{
			ID:         id,
			What:       "Potential file inclusion via variable",
			Severity:   issue.Medium,
			Confidence: issue.High,
		},
		cleanedVar: map[any]ast.Node{},
		joinedVar:  map[any]ast.Node{},
	}
	rule.pathJoin.Add("path/filepath", "Join")
	rule.pathJoin.Add("path", "Join")
	rule.clean.Add("path/filepath", "Clean")
	rule.clean.Add("path/filepath", "Rel")
	rule.clean.Add("path/filepath", "EvalSymlinks")
	rule.Add("io/ioutil", "ReadFile")
	rule.Add("os", "ReadFile")
	rule.Add("os", "Open")
	rule.Add("os", "OpenFile")
	rule.Add("os", "Create")
	return rule, []ast.Node{(*ast.CallExpr)(nil), (*ast.AssignStmt)(nil)}
}
