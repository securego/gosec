package rules

import (
	"fmt"
	"go/ast"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type secretSerialization struct {
	issue.MetaData
	pattern *regexp.Regexp
}

func (r *secretSerialization) ID() string {
	return r.MetaData.ID
}

func (r *secretSerialization) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	field, ok := n.(*ast.Field)
	if !ok || len(field.Names) == 0 {
		return nil, nil // skip embedded (anonymous) fields
	}

	// 1. Parse the JSON tag to determine behavior
	omitted := false
	jsonKey := ""

	if field.Tag != nil {
		if tagVal, err := strconv.Unquote(field.Tag.Value); err == nil {
			st := reflect.StructTag(tagVal)
			if tag := st.Get("json"); tag != "" {
				if tag == "-" {
					omitted = true
				} else {
					// "name,omitempty" -> "name"
					// "-," -> "-" (A field literally named "-")
					parts := strings.SplitN(tag, ",", 2)
					jsonKey = parts[0]
				}
			}
		}
	}

	if omitted {
		return nil, nil
	}

	// 2. Iterate over all names in this field definition
	// e.g., type T struct { Pass, Salt string }
	for _, nameIdent := range field.Names {
		fieldName := nameIdent.Name

		// Only check exported fields (JSON marshaler ignores unexported ones)
		if !ast.IsExported(fieldName) {
			continue
		}

		// Determine the effective key used in JSON
		effectiveKey := jsonKey
		if effectiveKey == "" {
			effectiveKey = fieldName
		}

		// 3. Heuristic Check
		// We match if EITHER the original field name OR the JSON key looks like a secret.
		// Case A: Field is named "Password" -> Match (even if json key is "p")
		// Case B: Field is named "Data" but json key is "auth_token" -> Match
		matched := false
		if r.pattern.MatchString(fieldName) {
			matched = true
		} else if r.pattern.MatchString(effectiveKey) {
			matched = true
		}

		if matched {
			msg := fmt.Sprintf("Exported struct field %q (JSON key %q) matches secret pattern", fieldName, effectiveKey)
			return ctx.NewIssue(field, r.ID(), msg, r.Severity, r.Confidence), nil
		}
	}

	return nil, nil
}

func NewSecretSerialization(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	// Refined pattern:
	// 1. (?i) case insensitive
	// 2. Looks for common exact matches or specific compound words
	// 3. Avoids generic suffixes by using strict groupings
	patternStr := `(?i)(password|passwd|pass|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key|bearer|cred|token)`

	if val, ok := conf[id]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			if p, ok := m["pattern"].(string); ok && p != "" {
				patternStr = p
			}
		}
	}

	return &secretSerialization{
		pattern: regexp.MustCompile(patternStr),
		MetaData: issue.MetaData{
			ID:         id,
			What:       "Exported struct field appears to be a secret and is not ignored by JSON marshaling",
			Severity:   issue.Medium,
			Confidence: issue.Medium,
		},
	}, []ast.Node{(*ast.Field)(nil)}
}
