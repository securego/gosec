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
	"go/types"
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type badTempFile struct {
	callListRule
	args          *regexp.Regexp
	argCalls      gosec.CallList
	nestedCalls   gosec.CallList
	openFileCalls gosec.CallList
}

// tempPathValue resolves string compile-time constants, including named
// constants and concatenations of constants.
func tempPathValue(n ast.Node, c *gosec.Context) (string, bool) {
	if expr, ok := n.(ast.Expr); ok {
		if tv, ok := c.Info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), true
		}
	}
	s, err := gosec.GetString(n)
	return s, err == nil
}

func (t *badTempFile) findTempDirArgs(n ast.Node, c *gosec.Context, suspect ast.Node) *issue.Issue {
	if s, ok := tempPathValue(suspect, c); ok {
		if gosec.RegexMatchWithCache(t.args, s) {
			return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence)
		}
		return nil
	}
	if ce := t.argCalls.ContainsPkgCallExpr(suspect, c, false); ce != nil {
		return c.NewIssue(n, t.ID(), t.What, t.Severity, t.Confidence)
	}
	if be, ok := suspect.(*ast.BinaryExpr); ok {
		if ops := gosec.GetBinaryExprOperands(be); len(ops) != 0 {
			return t.findTempDirArgs(n, c, ops[0])
		}
		return nil
	}
	if ce := t.nestedCalls.ContainsPkgCallExpr(suspect, c, false); ce != nil {
		return t.findTempDirArgs(n, c, ce.Args[0])
	}
	return nil
}

// createsFile reports whether the flag passed to os.OpenFile is a constant
// that includes O_CREATE. O_CREATE is looked up in the os package the code was
// type-checked against, as its value depends on the target platform.
func createsFile(call *ast.CallExpr, c *gosec.Context) bool {
	_, obj := gosec.GetCallObject(call, c)
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	create, ok := obj.Pkg().Scope().Lookup("O_CREATE").(*types.Const)
	if !ok {
		return false
	}
	tv, ok := c.Info.Types[call.Args[1]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	flag, ok := constant.Int64Val(tv.Value)
	mask, maskOK := constant.Int64Val(create.Val())
	return ok && maskOK && flag&mask != 0
}

func (t *badTempFile) Match(n ast.Node, c *gosec.Context) (gi *issue.Issue, err error) {
	if node := t.calls.ContainsPkgCallExpr(n, c, false); node != nil {
		return t.findTempDirArgs(n, c, node.Args[0]), nil
	}
	if node := t.openFileCalls.ContainsPkgCallExpr(n, c, false); node != nil && len(node.Args) == 3 {
		if createsFile(node, c) {
			return t.findTempDirArgs(n, c, node.Args[0]), nil
		}
	}
	return nil, nil
}

// NewBadTempFile detects direct writes to predictable path in temporary directory
func NewBadTempFile(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &badTempFile{
		callListRule:  newCallListRule(id, "File creation in shared tmp directory without using ioutil.Tempfile", issue.Medium, issue.High),
		args:          regexp.MustCompile(`^(/(usr|var))?/tmp(/.*)?$`),
		argCalls:      gosec.NewCallList(),
		nestedCalls:   gosec.NewCallList(),
		openFileCalls: gosec.NewCallList(),
	}
	rule.Add("io/ioutil", "WriteFile")
	rule.AddAll("os", "Create", "WriteFile")
	rule.openFileCalls.Add("os", "OpenFile")
	rule.argCalls.Add("os", "TempDir")
	rule.nestedCalls.AddAll("path", "Join")
	rule.nestedCalls.Add("path/filepath", "Join")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
