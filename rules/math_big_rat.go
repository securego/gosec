package rules

import (
	"fmt"
	"go/ast"

	"github.com/securego/gosec/v2"
)

type usingOldMathBig struct {
	gosec.MetaData
}

func (r *usingOldMathBig) ID() string {
	return r.MetaData.ID
}

func getXName(elem ast.Stmt) (*ast.IfStmt, string, error) {
	ifStmt, ok := elem.(*ast.IfStmt)
	if !ok {
		return nil, "", fmt.Errorf("not an if")
	}
	ifCond, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok {
		return nil, "", fmt.Errorf("not a BinaryExpr")
	}
	ifCondX, ok := ifCond.X.(*ast.Ident)
	if !ok {
		return nil, "", fmt.Errorf("X not an Ident")
	}
	return ifStmt, ifCondX.Name, nil
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

	funcDecl, funcDeclErr := gosec.FindFuncDecl(callExpr, ctx)
	if funcDeclErr != nil {
		return nil, nil
	}

	for _, elem := range funcDecl.Body.List {
		firstIf, firstName, err := getXName(elem)
		if err != nil {
			continue
		}
		if firstName != "exp5" {
			continue
		}
		for _, secondElem := range firstIf.Body.List {
			secondIf, secondName, err := getXName(secondElem)
			if err != nil {
				continue
			}
			if secondName != "n" {
				continue
			}
			hasIf := false
			for _, thirdElem := range secondIf.Body.List {
				_, _, err := getXName(thirdElem)
				if err != nil {
					continue
				}
				hasIf = true
			}
			if hasIf {
				return nil, nil
			}
			return gosec.NewIssue(ctx, node, r.ID(), r.What, r.Severity, r.Confidence), nil
		}
	}

	return nil, nil
}

// NewUsingOldMathBig rule detects the use of Rat.SetString from math/big.
func NewUsingOldMathBig(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	return &usingOldMathBig{
		MetaData: gosec.MetaData{
			ID:         id,
			What:       "Rat.SetString in math/big in has an overflow that can lead to Uncontrolled Memory Consumption (CVE-2022-23772)",
			Severity:   gosec.High,
			Confidence: gosec.High,
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
