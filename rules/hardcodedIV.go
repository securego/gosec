package rules

import (
	"go/ast"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

type usesHardcodedIV struct {
	issue.MetaData
	trackedFunctions map[string][]int
}

func (r *usesHardcodedIV) ID() string {
	return r.MetaData.ID
}

// The code is a little bit spaghetti and there are things that repeat
// Can be improved
func (r *usesHardcodedIV) Match(n ast.Node, c *gosec.Context) (*issue.Issue, error) {
	// cast n to a call expression, we can do that safely, because this match method gets only called when CallExpr node is found
	funcCall := n.(*ast.CallExpr)

	// cast to a function call from an object and get the function part; example: a.doSomething()

	if funcSelector, isSelector := funcCall.Fun.(*ast.SelectorExpr); isSelector {

		// Check if the call is actually made from an object
		if _, hasX := funcSelector.X.(*ast.Ident); hasX {

			//Iterate trough the wanted functions
			for functionName, functionNumArgsAndNoncePosArr := range r.trackedFunctions {

				// Check if the function name matches with the one we look for, and if the function accepts an exact number of arguments(rough function signature check)
				if funcSelector.Sel.Name == functionName && len(funcCall.Args) == functionNumArgsAndNoncePosArr[0] {

					// Check the type of the passed argument to the function
					switch trackedFunctionPassedArgType := funcCall.Args[functionNumArgsAndNoncePosArr[1]].(type) {

					// {} used
					case *ast.CompositeLit:
						// Check if the argument is static array
						if _, isArray := trackedFunctionPassedArgType.Type.(*ast.ArrayType); isArray {
							return c.NewIssue(n, r.ID(), r.What+" by passing hardcoded byte array", r.Severity, r.Confidence), nil
						}

					// () used
					case *ast.CallExpr:

						// Check if it's a function call, because []byte() is a function call, and also check if the number of arguments to this call is only 1
						switch trackedFunctionPassedArgType.Fun.(type) {
						case *ast.ArrayType:
							return c.NewIssue(n, r.ID(), r.What+" by converting static string to a byte array", r.Severity, r.Confidence), nil

						// Check if the argument passed is another function
						case *ast.FuncLit:
							functionCalled, _ := trackedFunctionPassedArgType.Fun.(*ast.FuncLit)

							// Check the type of the last statement in the anonymous function
							switch calledFunctionLastInstructionType := functionCalled.Body.List[len(functionCalled.Body.List)-1].(type) {

							case *ast.IfStmt:

								ifStatementContent := calledFunctionLastInstructionType.Body.List

								// check if the if statement has return statement
								if retStatement, isReturn := ifStatementContent[len(ifStatementContent)-1].(*ast.ReturnStmt); isReturn {
									argInNestedFunc := retStatement.Results[0]

									// check the type of the returned value
									switch argInNestedFunc.(type) {
									case *ast.CompositeLit:
										// Check if the argument is static array
										if _, isArray := argInNestedFunc.(*ast.CompositeLit).Type.(*ast.ArrayType); isArray {
											return c.NewIssue(n, r.ID(), r.What+" by passing hardcoded byte array in a function call", r.Severity, r.Confidence), nil
										}

									case *ast.CallExpr:
										if _, ok := argInNestedFunc.(*ast.CallExpr).Fun.(*ast.ArrayType); ok {
											return c.NewIssue(n, r.ID(), r.What+" by converting static string to a byte array in a function call", r.Severity, r.Confidence), nil
										}
									}
								}
							case *ast.ReturnStmt:

								argInNestedFunc := calledFunctionLastInstructionType.Results[0]
								switch argInNestedFunc.(type) {
								case *ast.CompositeLit:
									// Check if the argument is static array
									if _, isArray := argInNestedFunc.(*ast.CompositeLit).Type.(*ast.ArrayType); isArray {
										return c.NewIssue(n, r.ID(), r.What+" by passing hardcoded byte array in a function call", r.Severity, r.Confidence), nil
									}

								case *ast.CallExpr:
									if _, ok := argInNestedFunc.(*ast.CallExpr).Fun.(*ast.ArrayType); ok {
										return c.NewIssue(n, r.ID(), r.What+" by converting static string to a byte array in a function call", r.Severity, r.Confidence), nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// loop through the functions we are checking

	return nil, nil
}

func NewUsesHardCodedIV(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
	calls := make(map[string][]int)
	// Holds the function name as key, the number of arguments that the function accepts, and at which index of those accepted arguments is the nonce/IV
	// Example "Test" 3, 1 -- means the function "Test" which accepts 3 arguments, and has the nonce arg as second argument

	calls["Seal"] = []int{4, 1}
	calls["Open"] = []int{4, 1}
	calls["NewCBCDecrypter"] = []int{2, 1} //
	calls["NewCBCEncrypter"] = []int{2, 1} //
	calls["NewCFBDecrypter"] = []int{2, 1}
	calls["NewCFBEncrypter"] = []int{2, 1}
	calls["NewCTR"] = []int{2, 1} //
	calls["NewOFB"] = []int{2, 1} //

	rule := &usesHardcodedIV{
		trackedFunctions: calls,
		MetaData: issue.MetaData{
			ID:         id,
			Severity:   issue.High,
			Confidence: issue.Medium,
			What:       "Use of hardcoded IV/nonce for encryption",
		},
	}
	return rule, []ast.Node{(*ast.CallExpr)(nil)}
}
