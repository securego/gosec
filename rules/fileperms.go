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
	"regexp"

	gas "github.com/GoASTScanner/gas/core"
)

type FilePermissions struct {
	gas.MetaData
	pattern *regexp.Regexp
	mode    int64
}

func (r *FilePermissions) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := gas.MatchCall(n, r.pattern); node != nil {
		if val, err := gas.GetInt(node.Args[1]); err == nil && val > r.mode {
			return gas.NewIssue(c, n, r.What, r.Severity, r.Confidence), nil
		}
	}
	return nil, nil
}

func NewChmodPerms(conf map[string]interface{}) (r gas.Rule, n ast.Node) {
	mode := 0600
	r = &FilePermissions{
		pattern: regexp.MustCompile(`^os\.Chmod$`),
		mode:    (int64)(mode),
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       fmt.Sprintf("Expect chmod permissions to be %#o or less", mode),
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}

func NewMkdirPerms(conf map[string]interface{}) (r gas.Rule, n ast.Node) {
	mode := 0700
	r = &FilePermissions{
		pattern: regexp.MustCompile(`^(os\.Mkdir|os\.MkdirAll)$`),
		mode:    (int64)(mode),
		MetaData: gas.MetaData{
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       fmt.Sprintf("Expect directory permissions to be %#o or less", mode),
		},
	}
	n = (*ast.CallExpr)(nil)
	return
}
