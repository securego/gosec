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

	"github.com/securego/gosec/v2"
)

type slowloris struct {
	gosec.MetaData
}

func (r *slowloris) ID() string {
	return r.MetaData.ID
}

func containsReadHeaderTimeout(node *ast.CompositeLit) bool {
	if node == nil {
		return false
	}
	for _, elt := range node.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if ident, ok := kv.Key.(*ast.Ident); ok {
				if ident.Name == "ReadHeaderTimeout" || ident.Name == "ReadTimeout" {
					return true
				}
			}
		}
	}
	return false
}

func (r *slowloris) Match(n ast.Node, ctx *gosec.Context) (*gosec.Issue, error) {
	switch node := n.(type) {
	case *ast.CompositeLit:
		actualType := ctx.Info.TypeOf(node.Type)
		if actualType != nil && actualType.String() == "net/http.Server" {
			if !containsReadHeaderTimeout(node) {
				return gosec.NewIssue(ctx, node, r.ID(), r.What, r.Severity, r.Confidence), nil
			}
		}
	}
	return nil, nil
}

// NewSlowloris attempts to find the http.Server struct and check if the ReadHeaderTimeout is configured.
func NewSlowloris(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return &slowloris{
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server",
			Confidence: gosec.Low,
			Severity:   gosec.Medium,
		},
	}, []ast.Node{(*ast.CompositeLit)(nil)}
}
