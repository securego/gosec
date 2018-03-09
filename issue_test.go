package gas_test

import (
	"go/ast"

	"github.com/GoASTScanner/gas"
	"github.com/GoASTScanner/gas/rules"
	"github.com/GoASTScanner/gas/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
			v.Callback = func(n ast.Node, ctx *gas.Context) bool {
				if node, ok := n.(*ast.BasicLit); ok {
					target = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())

			issue := gas.NewIssue(ctx, target, "", gas.High, gas.High)
			Expect(issue).ShouldNot(BeNil())
			Expect(issue.Code).Should(MatchRegexp(`"bar"`))
			Expect(issue.Line).Should(Equal("2"))

		})

		It("should return an error if specific context is not able to be obtained", func() {
			Skip("Not implemented")
		})

		It("should provide accurate line and file information", func() {
			Skip("Not implemented")
		})

		It("should provide accurate line and file information for multi-line statements", func() {
			var target *ast.BinaryExpr

			source := `package main
			import "os"
			func main(){`
			source += "q := `SELECT * FROM table WHERE` + \n  os.Args[1] + `= ?` // nolint: gas\n"
			source += `println(q)}`

			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", source)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gas.Context) bool {
				if node, ok := n.(*ast.BinaryExpr); ok {
					target = node
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())

			// Use SQL rule to check binary expr
			cfg := gas.NewConfig()
			rule, _ := rules.NewSQLStrConcat("TEST", cfg)
			issue, err := rule.Match(target, ctx)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(issue).ShouldNot(BeNil())
			Expect(issue.File).Should(MatchRegexp("foo.go"))
			Expect(issue.Line).Should(MatchRegexp("3-4"))
		})

		It("should maintain the provided severity score", func() {
			Skip("Not implemented")
		})

		It("should maintain the provided confidence score", func() {
			Skip("Not implemented")
		})

	})

})
