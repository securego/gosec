package rules

import (
	"go/ast"
	"go/types"

	"github.com/securego/gas"
)

type archive struct {
	gas.MetaData
	calls   gas.CallList
	argType string
}

func (a *archive) ID() string {
	return a.MetaData.ID
}

// Match inspects AST nodes to determine if the filepath.Joins uses any argument derived from type zip.File
func (a *archive) Match(n ast.Node, c *gas.Context) (*gas.Issue, error) {
	if node := a.calls.ContainsCallExpr(n, c); node != nil {
		for _, arg := range node.Args {
			var argType types.Type
			if selector, ok := arg.(*ast.SelectorExpr); ok {
				argType = c.Info.TypeOf(selector.X)
			} else if ident, ok := arg.(*ast.Ident); ok {
				if ident.Obj != nil && ident.Obj.Kind == ast.Var {
					decl := ident.Obj.Decl
					if assign, ok := decl.(*ast.AssignStmt); ok {
						if selector, ok := assign.Rhs[0].(*ast.SelectorExpr); ok {
							argType = c.Info.TypeOf(selector.X)
						}
					}
				}
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
