package rules

import (
	"go/ast"
	"go/types"

	"github.com/GoASTScanner/gas"
)

type archive struct {
	gas.MetaData
	calls   gas.CallList
	argType string
}

func (a *archive) ID() string {
	return a.MetaData.ID
}

func (a *archive) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := a.calls.ContainsCallExpr(n, c); node != nil {
		for _, arg := range node.Args {
			var argType types.Type
			if selector, ok := arg.(*ast.SelectorExpr); ok {
				argType = c.Info.TypeOf(selector.X)
			} else if ident, ok := arg.(*ast.Ident); ok {
				argType = c.Info.TypeOf(ident)
			}

			if argType != nil && argType.String() == a.argType {
				return gas.NewIssue(c, n, a.ID(), a.What, a.Severity, a.Confidence), nil
			}
		}
	}
	return nil, nil
}

// NewArchive creates a new rule which detects the file traversal when extracting zip archives
func NewArchive(id string, conf gas.Config) (gas.Rule, []ast.Node) {
	calls := gas.NewCallList()
	calls.Add("path/filepath", "Join")
	return &archive{
		calls:   calls,
		argType: "*archive/zip.File",
		MetaData: gas.MetaData{
			ID:         id,
			Severity:   gas.Medium,
			Confidence: gas.High,
			What:       "File traversal when extracting zip archive",
		},
	}, []ast.Node{(*ast.CallExpr)(nil)}
}
