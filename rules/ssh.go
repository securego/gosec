package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type sshHostKey struct {
	callListRule
}

// NewSSHHostKey rule detects the use of insecure ssh HostKeyCallback.
func NewSSHHostKey(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := gosec.NewCallList()
	calls.Add("golang.org/x/crypto/ssh", "InsecureIgnoreHostKey")

	return &sshHostKey{callListRule{
		MetaData: issue.MetaData{
			RuleID:     id,
			What:       "Use of ssh InsecureIgnoreHostKey should be audited",
			Severity:   issue.Medium,
			Confidence: issue.High,
		},
		calls: calls,
	}}, []ast.Node{(*ast.CallExpr)(nil)}
}
