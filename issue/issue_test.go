package issue_test

import (
	"go/ast"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/rules"
	"github.com/securego/gosec/v2/testutils"
)

var _ = Describe("Issue", func() {
	Context("when creating a new issue", func() {
		It("should create a code snippet from the specified ast.Node", func() {
			var target *ast.BasicLit
			source := `package main
			const foo = "bar"
			func main(){
				println(foo)
			}
			`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", source)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BasicLit); ok {
					target = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())

			fobj := ctx.GetFileAtNodePos(target)
			issue := issue.New(fobj, target, "TEST", "", issue.High, issue.High)
			Expect(issue).ShouldNot(BeNil())
			Expect(issue.Code).Should(MatchRegexp(`"bar"`))
			Expect(issue.Line).Should(Equal("2"))
			Expect(issue.Col).Should(Equal("16"))
			Expect(issue.Cwe).Should(BeNil())
		})

		It("should return an error if specific context is not able to be obtained", func() {
			Skip("Not implemented")
		})

		It("should construct file path based on line and file information", func() {
			var target *ast.AssignStmt

			source := `package main
			import "fmt"
			func main() {
				username := "admin"
				password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
				fmt.Println("Doing something with: ", username, password)
			}`

			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", source)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.AssignStmt); ok {
					if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name == "password" {
						target = node
					}
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())

			// Use hardcoded rule to check assignment
			cfg := gosec.NewConfig()
			rule, _ := rules.NewHardcodedCredentials("TEST", cfg)
			foundIssue, err := rule.Match(target, ctx)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(foundIssue).ShouldNot(BeNil())
			Expect(foundIssue.FileLocation()).Should(MatchRegexp("foo.go:5"))
		})

		It("should provide accurate line and file information", func() {
			Skip("Not implemented")
		})

		It("should provide accurate line and file information for multi-line statements", func() {
			var target *ast.CallExpr
			source := `
package main
import (
   	"net"
)
func main() {
	_, _ := net.Listen("tcp", 
	"0.0.0.0:2000")
}
`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", source)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.CallExpr); ok {
					target = node
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())

			cfg := gosec.NewConfig()
			rule, _ := rules.NewBindsToAllNetworkInterfaces("TEST", cfg)
			issue, err := rule.Match(target, ctx)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(issue).ShouldNot(BeNil())
			Expect(issue.File).Should(MatchRegexp("foo.go"))
			Expect(issue.Line).Should(MatchRegexp("7-8"))
			Expect(issue.Col).Should(Equal("10"))
		})

		It("should maintain the provided severity score", func() {
			Skip("Not implemented")
		})

		It("should maintain the provided confidence score", func() {
			Skip("Not implemented")
		})
	})

	Describe("GetCweByRule", func() {
		It("should return correct CWE for valid rule IDs", func() {
			// Test SQL injection
			cwe := issue.GetCweByRule("G201")
			Expect(cwe).ShouldNot(BeNil())
			Expect(cwe.ID).Should(Equal("89"))

			// Test hardcoded credentials
			cwe = issue.GetCweByRule("G101")
			Expect(cwe).ShouldNot(BeNil())
			Expect(cwe.ID).Should(Equal("798"))

			// Test path traversal
			cwe = issue.GetCweByRule("G304")
			Expect(cwe).ShouldNot(BeNil())
			Expect(cwe.ID).Should(Equal("22"))
		})

		It("should return nil for unknown rule IDs", func() {
			cwe := issue.GetCweByRule("G999")
			Expect(cwe).Should(BeNil())
		})

		It("should return nil for empty rule ID", func() {
			cwe := issue.GetCweByRule("")
			Expect(cwe).Should(BeNil())
		})
	})

	Describe("Score", func() {
		It("should convert High to string", func() {
			score := issue.High
			Expect(score.String()).Should(Equal("HIGH"))
		})

		It("should convert Medium to string", func() {
			score := issue.Medium
			Expect(score.String()).Should(Equal("MEDIUM"))
		})

		It("should convert Low to string", func() {
			score := issue.Low
			Expect(score.String()).Should(Equal("LOW"))
		})

		It("should convert undefined score to UNDEFINED", func() {
			score := issue.Score(99)
			Expect(score.String()).Should(Equal("UNDEFINED"))
		})

		It("should marshal to JSON correctly", func() {
			score := issue.High
			jsonBytes, err := score.MarshalJSON()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(jsonBytes)).Should(Equal(`"HIGH"`))

			score = issue.Medium
			jsonBytes, err = score.MarshalJSON()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(jsonBytes)).Should(Equal(`"MEDIUM"`))

			score = issue.Low
			jsonBytes, err = score.MarshalJSON()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(jsonBytes)).Should(Equal(`"LOW"`))
		})
	})

	Describe("MetaData", func() {
		It("should create metadata with NewMetaData", func() {
			meta := issue.NewMetaData("G201", "SQL injection", issue.High, issue.Medium)
			Expect(meta.RuleID).Should(Equal("G201"))
			Expect(meta.What).Should(Equal("SQL injection"))
			Expect(meta.Severity).Should(Equal(issue.High))
			Expect(meta.Confidence).Should(Equal(issue.Medium))
		})

		It("should return rule ID via ID method", func() {
			meta := issue.NewMetaData("G101", "Hardcoded credentials", issue.High, issue.High)
			Expect(meta.ID()).Should(Equal("G101"))
		})
	})

	Describe("Issue methods", func() {
		It("should format FileLocation correctly", func() {
			iss := &issue.Issue{
				File: "/path/to/file.go",
				Line: "42",
			}
			Expect(iss.FileLocation()).Should(Equal("/path/to/file.go:42"))
		})

		It("should format FileLocation with line range", func() {
			iss := &issue.Issue{
				File: "test.go",
				Line: "10-15",
			}
			Expect(iss.FileLocation()).Should(Equal("test.go:10-15"))
		})

		It("should add suppressions with WithSuppressions", func() {
			iss := &issue.Issue{
				RuleID: "G101",
			}
			suppressions := []issue.SuppressionInfo{
				{Kind: "inSource", Justification: "false positive"},
				{Kind: "external", Justification: "accepted risk"},
			}
			result := iss.WithSuppressions(suppressions)
			Expect(result).Should(BeIdenticalTo(iss))
			Expect(iss.Suppressions).Should(HaveLen(2))
			Expect(iss.Suppressions[0].Kind).Should(Equal("inSource"))
			Expect(iss.Suppressions[0].Justification).Should(Equal("false positive"))
			Expect(iss.Suppressions[1].Kind).Should(Equal("external"))
		})
	})

	Describe("GetLine", func() {
		It("should return single line number", func() {
			source := `package main
func main() {
	x := 42
}
`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("test.go", source)
			ctx := pkg.CreateContext("test.go")

			var target ast.Node
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BasicLit); ok {
					target = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)

			fobj := ctx.GetFileAtNodePos(target)
			line := issue.GetLine(fobj, target)
			Expect(line).Should(Equal("3"))
		})

		It("should return line range for multi-line nodes", func() {
			source := `package main
func main() {
	x := "multi" +
		"line"
}
`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("test.go", source)
			ctx := pkg.CreateContext("test.go")

			var target ast.Node
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BinaryExpr); ok {
					target = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)

			if target != nil {
				fobj := ctx.GetFileAtNodePos(target)
				line := issue.GetLine(fobj, target)
				Expect(line).Should(MatchRegexp(`\d+-\d+`))
			}
		})
	})

	Describe("New with edge cases", func() {
		It("should handle nil node gracefully", func() {
			source := `package main
const foo = "bar"
`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("test.go", source)
			ctx := pkg.CreateContext("test.go")
			fobj := ctx.FileSet.File(ctx.Root.Pos())

			iss := issue.New(fobj, nil, "TEST", "test issue", issue.High, issue.High)
			Expect(iss).ShouldNot(BeNil())
			Expect(iss.RuleID).Should(Equal("TEST"))
			Expect(iss.Code).Should(ContainSubstring("invalid AST node"))
		})

		It("should set CWE automatically for known rules", func() {
			source := `package main
const foo = "bar"
`
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("test.go", source)
			ctx := pkg.CreateContext("test.go")

			var target *ast.BasicLit
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BasicLit); ok {
					target = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)

			fobj := ctx.GetFileAtNodePos(target)
			iss := issue.New(fobj, target, "G201", "SQL injection", issue.High, issue.High)
			Expect(iss.Cwe).ShouldNot(BeNil())
			Expect(iss.Cwe.ID).Should(Equal("89"))
		})
	})
})
