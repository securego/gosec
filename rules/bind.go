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
	"regexp"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

// Looks for net.Listen("0.0.0.0"), net.Listen("[::]:8080") or net.Listen(":8080")
type bindsToAllNetworkInterfaces struct {
	callListRule
	pattern *regexp.Regexp
}

func (r *bindsToAllNetworkInterfaces) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	callExpr := r.calls.ContainsPkgCallExpr(n, c, false)
	if callExpr == nil {
		return nil, nil
	}
	if len(callExpr.Args) > 1 {
		for _, value := range listenAddressValues(callExpr.Args[1], c) {
			if gosec.RegexMatchWithCache(r.pattern, value) {
				return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
			}
		}
	} else if len(callExpr.Args) > 0 {
		values := gosec.GetCallStringArgsValues(callExpr.Args[0], c)
		for _, value := range values {
			if gosec.RegexMatchWithCache(r.pattern, value) {
				return c.NewIssue(n, r.ID(), r.What, r.Severity, r.Confidence), nil
			}
		}
	}
	return nil, nil
}

// listenAddressValues returns the values of a listen address that can be resolved
// statically. For a string concatenation only the leading operand is resolved,
// because it holds the host part of the address (e.g. ":" + port).
func listenAddressValues(expr ast.Expr, c *gosec.Context) []string {
	if tv, ok := c.Info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return []string{constant.StringVal(tv.Value)}
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return gosec.GetIdentStringValues(e)
	case *ast.ParenExpr:
		return listenAddressValues(e.X, c)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return listenAddressValues(e.X, c)
		}
	}
	return nil
}

// NewBindsToAllNetworkInterfaces detects socket connections that are setup to
// listen on all network interfaces.
func NewBindsToAllNetworkInterfaces(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	rule := &bindsToAllNetworkInterfaces{
		callListRule: newCallListRule(id, "Binds to all network interfaces", issue.Medium, issue.High),
		pattern:      regexp.MustCompile(`^(0\.0\.0\.0|\[::\]|:).*$`),
	}
	rule.Add("net", "Listen").Add("crypto/tls", "Listen")
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
