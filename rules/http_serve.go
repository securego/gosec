package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type httpServeWithoutTimeouts struct {
	callListRule
}

// NewHTTPServeWithoutTimeouts detects use of net/http serve functions that have no support for setting timeouts.
func NewHTTPServeWithoutTimeouts(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.AddAll("net/http", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS")

	return &httpServeWithoutTimeouts{callListRule{
		MetaData: issue.MetaData{
			RuleID:     id,
			What:       "Use of net/http serve function that has no support for setting timeouts",
			Severity:   issue.Medium,
			Confidence: issue.High,
		},
		calls: calls,
	}}, []ast.Node{(*ast.CallExpr)(nil)}
}
