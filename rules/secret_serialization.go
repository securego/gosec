package rules

import (
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type secretSerialization struct {
	issue.MetaData
	pattern *regexp.Regexp
	cache   sync.Map
}

type sensitiveFieldMatch struct {
	fieldName string
	jsonKey   string
	found     bool
}

func (r *secretSerialization) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	callExpr, ok := n.(*ast.CallExpr)
	if !ok {
		return nil, nil
	}

	jsonArg := r.findJSONMarshalArgument(callExpr, ctx)
	if jsonArg == nil || ctx.Info == nil {
		return nil, nil
	}

	typ := ctx.Info.TypeOf(jsonArg)
	if typ == nil {
		return nil, nil
	}

	if match := r.findSensitiveFieldForType(typ); match.found {
		msg := fmt.Sprintf("Marshaled struct field %q (JSON key %q) matches secret pattern", match.fieldName, match.jsonKey)
		return ctx.NewIssue(callExpr, r.ID(), msg, r.Severity, r.Confidence), nil
	}

	return nil, nil
}

func (r *secretSerialization) findJSONMarshalArgument(callExpr *ast.CallExpr, ctx *gosec.Context) ast.Expr {
	if _, matched := gosec.MatchCallByPackage(callExpr, ctx, "encoding/json", "Marshal", "MarshalIndent"); matched {
		if len(callExpr.Args) > 0 {
			return callExpr.Args[0]
		}
		return nil
	}

	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel == nil || selector.Sel.Name != "Encode" || ctx.Info == nil {
		return nil
	}

	receiverType := ctx.Info.TypeOf(selector.X)
	if !isEncodingJSONEncoderType(receiverType) {
		return nil
	}

	if len(callExpr.Args) > 0 {
		return callExpr.Args[0]
	}

	return nil
}

func isEncodingJSONEncoderType(typ types.Type) bool {
	if typ == nil {
		return false
	}

	switch t := typ.(type) {
	case *types.Pointer:
		return isEncodingJSONEncoderType(t.Elem())
	case *types.Named:
		if obj := t.Obj(); obj != nil && obj.Name() == "Encoder" {
			if pkg := obj.Pkg(); pkg != nil && pkg.Path() == "encoding/json" {
				return true
			}
		}
	}

	return false
}

func (r *secretSerialization) findSensitiveFieldForType(typ types.Type) sensitiveFieldMatch {
	return r.findSensitiveFieldForTypeWithVisited(typ, make(map[types.Type]struct{}))
}

func (r *secretSerialization) findSensitiveFieldForTypeWithVisited(typ types.Type, visited map[types.Type]struct{}) sensitiveFieldMatch {
	if typ == nil {
		return sensitiveFieldMatch{}
	}

	if cached, ok := r.cache.Load(typ); ok {
		return cached.(sensitiveFieldMatch)
	}

	if _, seen := visited[typ]; seen {
		return sensitiveFieldMatch{}
	}
	visited[typ] = struct{}{}

	var match sensitiveFieldMatch

	switch t := typ.(type) {
	case *types.Named:
		match = r.findSensitiveFieldForTypeWithVisited(t.Underlying(), visited)
	case *types.Pointer:
		match = r.findSensitiveFieldForTypeWithVisited(t.Elem(), visited)
	case *types.Struct:
		match = r.findSensitiveSerializedField(t)
	case *types.Slice:
		match = r.findSensitiveFieldForTypeWithVisited(t.Elem(), visited)
	case *types.Array:
		match = r.findSensitiveFieldForTypeWithVisited(t.Elem(), visited)
	case *types.Map:
		match = r.findSensitiveFieldForTypeWithVisited(t.Elem(), visited)
	case *types.Interface:
		for i := 0; i < t.NumEmbeddeds(); i++ {
			match = r.findSensitiveFieldForTypeWithVisited(t.EmbeddedType(i), visited)
			if match.found {
				break
			}
		}
	}

	r.cache.Store(typ, match)
	return match
}

func (r *secretSerialization) findSensitiveSerializedField(st *types.Struct) sensitiveFieldMatch {
	if st == nil {
		return sensitiveFieldMatch{}
	}

	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		if field == nil || !field.Exported() || field.Name() == "_" {
			continue
		}

		if !isSecretCandidateType(field.Type()) {
			continue
		}

		effectiveKey, omitted := jsonNameFromStructTag(field.Name(), st.Tag(i))
		if omitted {
			continue
		}

		if gosec.RegexMatchWithCache(r.pattern, field.Name()) || gosec.RegexMatchWithCache(r.pattern, effectiveKey) {
			return sensitiveFieldMatch{fieldName: field.Name(), jsonKey: effectiveKey, found: true}
		}
	}

	return sensitiveFieldMatch{}
}

func isSecretCandidateType(typ types.Type) bool {
	switch t := typ.(type) {
	case *types.Named:
		return isSecretCandidateType(t.Underlying())
	case *types.Basic:
		return t.Kind() == types.String
	case *types.Pointer:
		return isSecretCandidateType(t.Elem())
	case *types.Slice:
		if elemBasic, ok := t.Elem().(*types.Basic); ok && elemBasic.Kind() == types.Uint8 {
			return true
		}
		return isSecretCandidateType(t.Elem())
	case *types.Array:
		if elemBasic, ok := t.Elem().(*types.Basic); ok && elemBasic.Kind() == types.Uint8 {
			return true
		}
		return isSecretCandidateType(t.Elem())
	}

	return false
}

func jsonNameFromStructTag(defaultName, tag string) (name string, omitted bool) {
	if tag == "" {
		return defaultName, false
	}

	jsonTag := reflect.StructTag(tag).Get("json")
	if jsonTag == "" {
		return defaultName, false
	}
	if jsonTag == "-" {
		return "", true
	}

	name = jsonTag
	if idx := strings.IndexByte(jsonTag, ','); idx >= 0 {
		name = jsonTag[:idx]
	}

	if name == "" {
		return defaultName, false
	}

	return name, false
}

func NewSecretSerialization(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	patternStr := `(?i)\b((?:api|access|auth|bearer|client|oauth|private|refresh|session|jwt)[_-]?(?:key|secret|token)s?|password|passwd|pwd|pass|secret|cred|jwt)\b`

	if val, ok := conf[id]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			if p, ok := m["pattern"].(string); ok && p != "" {
				patternStr = p
			}
		}
	}

	return &secretSerialization{
		pattern:  regexp.MustCompile(patternStr),
		MetaData: issue.NewMetaData(id, "Exported struct field appears to be a secret and is not ignored by JSON marshaling", issue.Medium, issue.Medium),
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
