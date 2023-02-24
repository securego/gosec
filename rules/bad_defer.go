package rules

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type deferType struct {
	typ     string
	methods []string
}

type badDefer struct {
	issue.MetaData
	types []deferType
}

func (r *badDefer) ID() string {
	return r.MetaData.ID
}

func normalize(typ string) string {
	return strings.TrimPrefix(typ, "*")
}

func contains(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func (r *badDefer) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	if deferStmt, ok := n.(*ast.DeferStmt); ok {
		for _, deferTyp := range r.types {
			if typ, method, err := gosec.GetCallInfo(deferStmt.Call, c); err == nil {
				if normalize(typ) == deferTyp.typ && contains(deferTyp.methods, method) {
					return c.NewIssue(n, r.ID(), fmt.Sprintf(r.What, method, typ), r.Severity, r.Confidence), nil
				}
			}
		}
	}

	return nil, nil
}

// NewDeferredClosing detects unsafe defer of error returning methods
func NewDeferredClosing(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	// Unhandled error in defer statement is only unsafe in writable files
	// See for moe details: https://www.joeshaw.org/dont-defer-close-on-writable-files/
	return &badDefer{
		types: []deferType{
			{
				typ:     "os.File",
				methods: []string{"Close"},
			},
			{
				typ:     "io.WriteCloser",
				methods: []string{"Close"},
			},
			{
				typ:     "io.ReadWriteCloser",
				methods: []string{"Close"},
			},
			{
				typ:     "io.Closer",
				methods: []string{"Close"},
			},
			{
				typ:     "net.Conn",
				methods: []string{"Close"},
			},
			{
				typ:     "net.Listener",
				methods: []string{"Close"},
			},
		},
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.Medium,
			Confidence: issue.High,
			What:       "Deferring unsafe method %q on type %q",
		},
	}, []ast.Node{(*ast.DeferStmt)(nil)}
}
