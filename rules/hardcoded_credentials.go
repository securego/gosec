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
	"go/token"
	"regexp"
	"strconv"

	zxcvbn "github.com/ccojocar/zxcvbn-go"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type credentials struct {
	issue.MetaData
	pattern          *regexp.Regexp
	patternValue     *regexp.Regexp // Pattern for matching string values (LHS on assign statements)
	entropyThreshold float64
	perCharThreshold float64
	truncate         int
	ignoreEntropy    bool
}

func (r *credentials) ID() string {
	return r.MetaData.ID
}

func truncate(s string, n int) string {
	if n > len(s) {
		return s
	}
	return s[:n]
}

func (r *credentials) isHighEntropyString(str string) bool {
	s := truncate(str, r.truncate)
	info := zxcvbn.PasswordStrength(s, []string{})
	entropyPerChar := info.Entropy / float64(len(s))
	return (info.Entropy >= r.entropyThreshold ||
		(info.Entropy >= (r.entropyThreshold/2) &&
			entropyPerChar >= r.perCharThreshold))
}

func (r *credentials) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return r.matchAssign(node, ctx)
	case *ast.ValueSpec:
		return r.matchValueSpec(node, ctx)
	case *ast.BinaryExpr:
		return r.matchEqualityCheck(node, ctx)
	}
	return nil, nil
}

func (r *credentials) matchAssign(assign *ast.AssignStmt, ctx *gosec.Context) (*issue.Issue, error) {
	for _, i := range assign.Lhs {
		if ident, ok := i.(*ast.Ident); ok {
			// First check LHS to find anything being assigned to variables whose name appears to be a cred
			if r.pattern.MatchString(ident.Name) {
				for _, e := range assign.Rhs {
					if val, err := gosec.GetString(e); err == nil {
						if r.ignoreEntropy || (!r.ignoreEntropy && r.isHighEntropyString(val)) {
							return ctx.NewIssue(assign, r.ID(), r.What, r.Severity, r.Confidence), nil
						}
					}
				}
			}

			// Now that no names were matched, match the RHS to see if the actual values being assigned are creds
			for _, e := range assign.Rhs {
				val, err := gosec.GetString(e)
				if err != nil {
					continue
				}

				if r.patternValue.MatchString(val) {
					if r.ignoreEntropy || r.isHighEntropyString(val) {
						return ctx.NewIssue(assign, r.ID(), r.What, r.Severity, r.Confidence), nil
					}
				}
			}
		}
	}
	return nil, nil
}

func (r *credentials) matchValueSpec(valueSpec *ast.ValueSpec, ctx *gosec.Context) (*issue.Issue, error) {
	// Running match against the variable name(s) first. Will catch any creds whose var name matches the pattern,
	// then will go back over to check the values themselves.
	for index, ident := range valueSpec.Names {
		if r.pattern.MatchString(ident.Name) && valueSpec.Values != nil {
			// const foo, bar = "same value"
			if len(valueSpec.Values) <= index {
				index = len(valueSpec.Values) - 1
			}
			if val, err := gosec.GetString(valueSpec.Values[index]); err == nil {
				if r.ignoreEntropy || (!r.ignoreEntropy && r.isHighEntropyString(val)) {
					return ctx.NewIssue(valueSpec, r.ID(), r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}

	// Now that no variable names have been matched, match the actual values to find any creds
	for _, ident := range valueSpec.Values {
		if val, err := gosec.GetString(ident); err == nil {
			if r.patternValue.MatchString(val) {
				if r.ignoreEntropy || r.isHighEntropyString(val) {
					return ctx.NewIssue(valueSpec, r.ID(), r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}

	return nil, nil
}

func (r *credentials) matchEqualityCheck(binaryExpr *ast.BinaryExpr, ctx *gosec.Context) (*issue.Issue, error) {
	if binaryExpr.Op == token.EQL || binaryExpr.Op == token.NEQ {
		ident, ok := binaryExpr.X.(*ast.Ident)
		if !ok {
			ident, _ = binaryExpr.Y.(*ast.Ident)
		}

		if ident != nil && r.pattern.MatchString(ident.Name) {
			valueNode := binaryExpr.Y
			if !ok {
				valueNode = binaryExpr.X
			}
			if val, err := gosec.GetString(valueNode); err == nil {
				if r.ignoreEntropy || (!r.ignoreEntropy && r.isHighEntropyString(val)) {
					return ctx.NewIssue(binaryExpr, r.ID(), r.What, r.Severity, r.Confidence), nil
				}
			}
		}

		// Now that the variable names have been checked, and no matches were found, make sure that
		// either the left or right operands is a string literal so we can match the value.
		identStrConst, ok := binaryExpr.X.(*ast.BasicLit)
		if !ok {
			identStrConst, ok = binaryExpr.Y.(*ast.BasicLit)
		}

		if ok && identStrConst.Kind == token.STRING {
			s, _ := gosec.GetString(identStrConst)
			if r.patternValue.MatchString(s) {
				if r.ignoreEntropy || r.isHighEntropyString(s) {
					return ctx.NewIssue(binaryExpr, r.ID(), r.What, r.Severity, r.Confidence), nil
				}
			}
		}
	}
	return nil, nil
}

// NewHardcodedCredentials attempts to find high entropy string constants being
// assigned to variables that appear to be related to credentials.
func NewHardcodedCredentials(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	pattern := `(?i)passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred`
	patternValue := "(?i)(^(.*[:;,](\\s)*)?[a-f0-9]{64}$)|(AIza[0-9A-Za-z-_]{35})|(^(.*[:;,](\\s)*)?github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$)|(^(.*[:;,](\\s)*)?[0-9a-zA-Z-_]{24}$)"
	entropyThreshold := 80.0
	perCharThreshold := 3.0
	ignoreEntropy := false
	truncateString := 16
	if val, ok := conf[id]; ok {
		conf := val.(map[string]interface{})
		if configPattern, ok := conf["pattern"]; ok {
			if cfgPattern, ok := configPattern.(string); ok {
				pattern = cfgPattern
			}
		}

		if configPatternValue, ok := conf["patternValue"]; ok {
			if cfgPatternValue, ok := configPatternValue.(string); ok {
				patternValue = cfgPatternValue
			}
		}

		if configIgnoreEntropy, ok := conf["ignore_entropy"]; ok {
			if cfgIgnoreEntropy, ok := configIgnoreEntropy.(bool); ok {
				ignoreEntropy = cfgIgnoreEntropy
			}
		}
		if configEntropyThreshold, ok := conf["entropy_threshold"]; ok {
			if cfgEntropyThreshold, ok := configEntropyThreshold.(string); ok {
				if parsedNum, err := strconv.ParseFloat(cfgEntropyThreshold, 64); err == nil {
					entropyThreshold = parsedNum
				}
			}
		}
		if configCharThreshold, ok := conf["per_char_threshold"]; ok {
			if cfgCharThreshold, ok := configCharThreshold.(string); ok {
				if parsedNum, err := strconv.ParseFloat(cfgCharThreshold, 64); err == nil {
					perCharThreshold = parsedNum
				}
			}
		}
		if configTruncate, ok := conf["truncate"]; ok {
			if cfgTruncate, ok := configTruncate.(string); ok {
				if parsedInt, err := strconv.Atoi(cfgTruncate); err == nil {
					truncateString = parsedInt
				}
			}
		}
	}

	return &credentials{
		pattern:          regexp.MustCompile(pattern),
		patternValue:     regexp.MustCompile(patternValue),
		entropyThreshold: entropyThreshold,
		perCharThreshold: perCharThreshold,
		ignoreEntropy:    ignoreEntropy,
		truncate:         truncateString,
		MetaData: issue.MetaData{
			ID:         id,
			What:       "Potential hardcoded credentials",
			Confidence: issue.Low,
			Severity:   issue.High,
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil), (*ast.BinaryExpr)(nil)}
}
