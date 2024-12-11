# Contributing

## Adding a new rule
New rules can be implemented in two ways:
- as a `gosec.Rule` -- these define an arbitrary function which will be called on every AST node in the analyzed file, and are appropriate for rules that mostly need to reason about a single statement.
- as an Analyzer -- these can operate on the entire program, and receive an [SSA](https://pkg.go.dev/golang.org/x/tools/go/ssa) representation of the program. This type of rule is useful when you need to perform a more complex analysis that requires a great deal of program context. 

### Adding a gosec.Rule
1. Copy an existing rule file as a starting point-- `./rules/unsafe.go` is a good option, as it implements a very simple rule with no additional supporting logic. Put the copied file in the `./rules/` directory.
2. Change the name of the rule constructor function and of the types in the rule file you've copied so they will be unique.
3. Edit the `Generate` function in `./rules/rulelist.go` to include your rule.
4. Use `make` to compile `gosec`. The binary will now contain your rule.

To make your rule actually useful, you will likely want to use the support functions defined in `./resolve.go`, `./helpers.go` and `./call_list.go`. There are inline comments explaining the purpose of most of these functions, and you can find usage examples in the existing rule files.

### Adding an Analyzer
1. Create a new go file under `./analyzers/` with the following scaffolding in it:
```go
package analyzers

import (
        "fmt"

        "golang.org/x/tools/go/analysis"
        "golang.org/x/tools/go/analysis/passes/buildssa"
        "github.com/securego/gosec/v2/issue"
)

const defaultIssueDescriptionMyAnalyzer = "My new analyzer!"

func newMyAnalyzer(id string, description string) *analysis.Analyzer {
        return &analysis.Analyzer{
                Name:     id,
                Doc:      description,
                Run:      runMyAnalyzer,
                Requires: []*analysis.Analyzer{buildssa.Analyzer},
        }
}

func runMyAnalyzer(pass *analysis.Pass) (interface{}, error) {
        ssaResult, err := getSSAResult(pass)
        if err != nil {
                return nil, fmt.Errorf("building ssa representation: %w", err)
        }
        var issues []*issue.Issue

        

        return issues, nil
}
```

2. Add the analyzer to `./analyzers/analyzerslist.go` in the `defaultAnalyzers` variable under an entry like `{"G999", "My test analyzer", newMyAnalyzer}`
3. `make`; then run the `gosec` binary produced. You should see the output from our print statement.
4. You now have a working example analyzer to play with-- look at the other implemented analyzers for ideas on how to make useful rules.
