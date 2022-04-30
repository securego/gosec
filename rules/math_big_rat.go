package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
)

type usingOldMathBig struct {
	gosec.MetaData
}

func (r *usingOldMathBig) ID() string {
	return r.MetaData.ID
}

func (r *usingOldMathBig) Match(node ast.Node, ctx *gosec.Context) (gi *gosec.Issue, err error) {
	callExpr, callExprOk := node.(*ast.CallExpr)
	if !callExprOk {
		return nil, nil
	}

	packageName, callName, callInfoOk := gosec.GetCallInfo(callExpr, ctx)
	if callInfoOk != nil {
		return nil, nil
	}

	if packageName != "math/big.Rat" || callName != "SetString" {
		return nil, nil
	}

	confidence := gosec.Low
	major, minor, build := gosec.GoVersion()
	if major == 1 && (minor == 16 && build < 14 || minor == 17 && build < 7) {
		confidence = gosec.Medium
	}

	return gosec.NewIssue(ctx, node, r.ID(), r.What, r.Severity, confidence), nil
}

// NewUsingOldMathBig rule detects the use of Rat.SetString from math/big.
func NewUsingOldMathBig(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	return &usingOldMathBig{
		MetaData: gosec.MetaData{
			ID:       id,
			What:     "Potential uncontrolled memory consumption in Rat.SetString (CVE-2022-23772)",
			Severity: gosec.High,
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
