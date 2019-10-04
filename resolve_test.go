package gosec_test

import (
	"go/ast"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/securego/gosec"
	"github.com/securego/gosec/testutils"
)

var _ = Describe("Resolve ast node to concrete value", func() {
	Context("when attempting to resolve an ast node", func() {
		It("should successfully resolve basic literal", func() {
			var basicLiteral *ast.BasicLit

			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `package main; const foo = "bar"; func main(){}`)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BasicLit); ok {
					basicLiteral = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(basicLiteral).ShouldNot(BeNil())
			Expect(gosec.TryResolve(basicLiteral, ctx)).Should(BeTrue())
		})

		It("should successfully resolve identifier", func() {
			var ident *ast.Ident
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `package main; var foo string = "bar"; func main(){}`)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.Ident); ok {
					ident = node
					return false
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(ident).ShouldNot(BeNil())
			Expect(gosec.TryResolve(ident, ctx)).Should(BeTrue())
		})

		It("should successfully resolve assign statement", func() {
			var assign *ast.AssignStmt
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `package main; const x = "bar"; func main(){ y := x; println(y) }`)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.AssignStmt); ok {
					if id, ok := node.Lhs[0].(*ast.Ident); ok && id.Name == "y" {
						assign = node
					}
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(assign).ShouldNot(BeNil())
			Expect(gosec.TryResolve(assign, ctx)).Should(BeTrue())
		})

		It("should successfully resolve a binary statement", func() {
			var target *ast.BinaryExpr
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `package main; const (x = "bar"; y = "baz"); func main(){ z := x + y; println(z) }`)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.BinaryExpr); ok {
					target = node
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(target).ShouldNot(BeNil())
			Expect(gosec.TryResolve(target, ctx)).Should(BeTrue())
		})
		It("should successfully resolve value spec", func() {
			var value *ast.ValueSpec
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("foo.go", `package main; const x = "bar"; func main(){ var y string = x; println(y) }`)
			ctx := pkg.CreateContext("foo.go")
			v := testutils.NewMockVisitor()
			v.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if node, ok := n.(*ast.ValueSpec); ok {
					if len(node.Names) == 1 && node.Names[0].Name == "y" {
						value = node
					}
				}
				return true
			}
			v.Context = ctx
			ast.Walk(v, ctx.Root)
			Expect(value).ShouldNot(BeNil())
			Expect(gosec.TryResolve(value, ctx)).Should(BeTrue())
		})

	})

})
