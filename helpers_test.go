package gosec_test

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/testutils"
)

var _ = Describe("Helpers", func() {
	Context("when listing package paths", func() {
		var dir string
		JustBeforeEach(func() {
			dir = GinkgoT().TempDir()
			_, err := os.MkdirTemp(dir, "test*.go")
			Expect(err).ShouldNot(HaveOccurred())
		})
		It("should return the root directory as package path", func() {
			paths, err := gosec.PackagePaths(dir, nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should return the package path", func() {
			paths, err := gosec.PackagePaths(dir+"/...", nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should exclude folder", func() {
			nested := dir + "/vendor"
			err := os.Mkdir(nested, 0o755)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = os.Create(nested + "/test.go")
			Expect(err).ShouldNot(HaveOccurred())
			exclude, err := regexp.Compile(`([\\/])?vendor([\\/])?`)
			Expect(err).ShouldNot(HaveOccurred())
			paths, err := gosec.PackagePaths(dir+"/...", []*regexp.Regexp{exclude})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should exclude folder with subpath", func() {
			nested := dir + "/pkg/generated"
			err := os.MkdirAll(nested, 0o755)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = os.Create(nested + "/test.go")
			Expect(err).ShouldNot(HaveOccurred())
			exclude, err := regexp.Compile(`([\\/])?/pkg\/generated([\\/])?`)
			Expect(err).ShouldNot(HaveOccurred())
			paths, err := gosec.PackagePaths(dir+"/...", []*regexp.Regexp{exclude})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(Equal([]string{dir}))
		})
		It("should be empty when folder does not exist", func() {
			nested := dir + "/test"
			paths, err := gosec.PackagePaths(nested+"/...", nil)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(paths).Should(BeEmpty())
		})
	})

	Context("when getting the root path", func() {
		It("should return the absolute path from relative path", func() {
			base := "test"
			cwd, err := os.Getwd()
			Expect(err).ShouldNot(HaveOccurred())
			root, err := gosec.RootPath(base)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(root).Should(Equal(filepath.Join(cwd, base)))
		})
		It("should return the absolute path from ellipsis path", func() {
			base := "test"
			cwd, err := os.Getwd()
			Expect(err).ShouldNot(HaveOccurred())
			root, err := gosec.RootPath(filepath.Join(base, "..."))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(root).Should(Equal(filepath.Join(cwd, base)))
		})
	})

	Context("when excluding the dirs", func() {
		It("should create a proper regexp", func() {
			r := gosec.ExcludedDirsRegExp([]string{"test"})
			Expect(r).Should(HaveLen(1))
			match := r[0].MatchString("/home/go/src/project/test/pkg")
			Expect(match).Should(BeTrue())
			match = r[0].MatchString("/home/go/src/project/vendor/pkg")
			Expect(match).Should(BeFalse())
		})

		It("should create a proper regexp for dir with subdir", func() {
			r := gosec.ExcludedDirsRegExp([]string{`test/generated`})
			Expect(r).Should(HaveLen(1))
			match := r[0].MatchString("/home/go/src/project/test/generated")
			Expect(match).Should(BeTrue())
			match = r[0].MatchString("/home/go/src/project/test/pkg")
			Expect(match).Should(BeFalse())
			match = r[0].MatchString("/home/go/src/project/vendor/pkg")
			Expect(match).Should(BeFalse())
		})

		It("should create no regexp when dir list is empty", func() {
			r := gosec.ExcludedDirsRegExp(nil)
			Expect(r).Should(BeEmpty())
			r = gosec.ExcludedDirsRegExp([]string{})
			Expect(r).Should(BeEmpty())
		})
	})

	Context("when getting call info", func() {
		It("should return the type and call name for selector expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "bytes"
			)

			func main() {
			    b := new(bytes.Buffer)
				_, err := b.WriteString("test")
				if err != nil {
				    panic(err)
				}
			}
			`)
			ctx := pkg.CreateContext("main.go")
			result := map[string]string{}
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				typeName, call, err := gosec.GetCallInfo(n, ctx)
				if err == nil {
					result[typeName] = call
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			Expect(result).Should(HaveKeyWithValue("*bytes.Buffer", "WriteString"))
		})

		It("should return the type and call name for new selector expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "bytes"
			)

			func main() {
				_, err := new(bytes.Buffer).WriteString("test")
				if err != nil {
				    panic(err)
				}
			}
			`)
			ctx := pkg.CreateContext("main.go")
			result := map[string]string{}
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				typeName, call, err := gosec.GetCallInfo(n, ctx)
				if err == nil {
					result[typeName] = call
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			Expect(result).Should(HaveKeyWithValue("bytes.Buffer", "WriteString"))
		})

		It("should return the type and call name for function selector expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "bytes"
			)

			func createBuffer() *bytes.Buffer {
			    return new(bytes.Buffer)
			}

			func main() {
				_, err := createBuffer().WriteString("test")
				if err != nil {
				    panic(err)
				}
			}
			`)
			ctx := pkg.CreateContext("main.go")
			result := map[string]string{}
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				typeName, call, err := gosec.GetCallInfo(n, ctx)
				if err == nil {
					result[typeName] = call
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			Expect(result).Should(HaveKeyWithValue("*bytes.Buffer", "WriteString"))
		})

		It("should return the type and call name for package function", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "fmt"
			)

			func main() {
			    fmt.Println("test")
			}
			`)
			ctx := pkg.CreateContext("main.go")
			result := map[string]string{}
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				typeName, call, err := gosec.GetCallInfo(n, ctx)
				if err == nil {
					result[typeName] = call
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			Expect(result).Should(HaveKeyWithValue("fmt", "Println"))
		})

		It("should return the type and call name when built-in new function is overridden", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
      package main

      type S struct{ F int }

      func (f S) Fun() {}

      func new() S { return S{} }

      func main() {
	      new().Fun()
      }
			`)
			ctx := pkg.CreateContext("main.go")
			result := map[string]string{}
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				typeName, call, err := gosec.GetCallInfo(n, ctx)
				if err == nil {
					result[typeName] = call
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			Expect(result).Should(HaveKeyWithValue("main", "new"))
		})
	})
	Context("when getting binary expression operands", func() {
		It("should return all operands of a binary expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "fmt"
			)

			func main() {
				be := "test1" + "test2"
				fmt.Println(be)
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var be *ast.BinaryExpr
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if expr, ok := n.(*ast.BinaryExpr); ok {
					be = expr
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			operands := gosec.GetBinaryExprOperands(be)
			Expect(operands).Should(HaveLen(2))
		})
		It("should return all operands of complex binary expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main

			import(
			    "fmt"
			)

			func main() {
				be := "test1" + "test2" + "test3" + "test4"
				fmt.Println(be)
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var be *ast.BinaryExpr
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if expr, ok := n.(*ast.BinaryExpr); ok {
					if be == nil {
						be = expr
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)

			operands := gosec.GetBinaryExprOperands(be)
			Expect(operands).Should(HaveLen(4))
		})
	})

	Context("when transforming build tags to cli build flags", func() {
		It("should return an empty slice when no tags are provided", func() {
			result := gosec.CLIBuildTags([]string{})
			Expect(result).To(BeEmpty())
		})

		It("should return a single -tags flag when one tag is provided", func() {
			result := gosec.CLIBuildTags([]string{"integration"})
			Expect(result).To(Equal([]string{"-tags=integration"}))
		})

		It("should combine multiple tags into a single -tags flag", func() {
			result := gosec.CLIBuildTags([]string{"linux", "amd64", "netgo"})
			Expect(result).To(Equal([]string{"-tags=linux,amd64,netgo"}))
		})

		It("should trim and ignore empty tags", func() {
			result := gosec.CLIBuildTags([]string{" linux ", "", "amd64"})
			Expect(result).To(Equal([]string{"-tags=linux,amd64"}))
		})
	})

	Context("when finding module root", func() {
		It("should find go.mod in parent directory", func() {
			tmpDir := GinkgoT().TempDir()
			gomodPath := filepath.Join(tmpDir, "go.mod")
			err := os.WriteFile(gomodPath, []byte("module test\n"), 0o600)
			Expect(err).ShouldNot(HaveOccurred())

			subDir := filepath.Join(tmpDir, "sub", "pkg")
			err = os.MkdirAll(subDir, 0o755)
			Expect(err).ShouldNot(HaveOccurred())

			result := gosec.FindModuleRoot(subDir)
			Expect(result).To(Equal(tmpDir))
		})

		It("should find nearest go.mod in nested module", func() {
			tmpDir := GinkgoT().TempDir()
			rootGomod := filepath.Join(tmpDir, "go.mod")
			err := os.WriteFile(rootGomod, []byte("module example.com/root\n"), 0o600)
			Expect(err).ShouldNot(HaveOccurred())

			nestedMod := filepath.Join(tmpDir, "nested", "mod")
			err = os.MkdirAll(nestedMod, 0o755)
			Expect(err).ShouldNot(HaveOccurred())
			nestedGomod := filepath.Join(nestedMod, "go.mod")
			err = os.WriteFile(nestedGomod, []byte("module example.com/nested/mod\n"), 0o600)
			Expect(err).ShouldNot(HaveOccurred())

			nestedPkg := filepath.Join(nestedMod, "pkg")
			err = os.MkdirAll(nestedPkg, 0o755)
			Expect(err).ShouldNot(HaveOccurred())

			result := gosec.FindModuleRoot(nestedPkg)
			Expect(result).To(Equal(nestedMod))
		})
	})

	Context("when getting integer values", func() {
		It("should extract integer from BasicLit", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 42
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var intVal int64
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.INT {
					val, err := gosec.GetInt(lit)
					if err == nil {
						intVal = val
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(intVal).To(Equal(int64(42)))
		})

		It("should return error for non-integer node", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := "not a number"
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			foundError := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					_, err := gosec.GetInt(lit)
					if err != nil {
						foundError = true
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundError).To(BeTrue())
		})
	})

	Context("when getting float values", func() {
		It("should extract float from BasicLit", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 3.14
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var floatVal float64
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.FLOAT {
					val, err := gosec.GetFloat(lit)
					if err == nil {
						floatVal = val
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(floatVal).To(Equal(3.14))
		})

		It("should return error for non-float node", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 42
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			foundError := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.INT {
					_, err := gosec.GetFloat(lit)
					if err != nil {
						foundError = true
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundError).To(BeTrue())
		})
	})

	Context("when getting char values", func() {
		It("should extract char from BasicLit", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 'A'
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var charVal byte
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.CHAR {
					val, err := gosec.GetChar(lit)
					if err == nil {
						charVal = val
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(charVal).To(Equal(byte('\'')))
		})

		It("should return error for non-char node", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 42
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			foundError := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.INT {
					_, err := gosec.GetChar(lit)
					if err != nil {
						foundError = true
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundError).To(BeTrue())
		})
	})

	Context("when getting string recursively", func() {
		It("should extract concatenated strings from binary expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := "Hello, " + "World!"
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var result string
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if binExpr, ok := n.(*ast.BinaryExpr); ok {
					val, err := gosec.GetStringRecursive(binExpr)
					if err == nil && val != "" {
						result = val
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(result).To(Equal("Hello, World!"))
		})

		It("should extract string from basic literal", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := "single string"
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var result string
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val, err := gosec.GetStringRecursive(lit)
					if err == nil {
						result = val
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(result).To(Equal("single string"))
		})

		It("should return empty string for non-string node", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 42 + 10
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			foundEmpty := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if binExpr, ok := n.(*ast.BinaryExpr); ok {
					if lit, ok := binExpr.X.(*ast.BasicLit); ok && lit.Kind == token.INT {
						val, err := gosec.GetStringRecursive(binExpr)
						if err == nil && val == "" {
							foundEmpty = true
						}
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundEmpty).To(BeTrue())
		})
	})

	Context("when matching composite literals", func() {
		It("should match composite literal by type", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			import "net/http"
			func main() {
				_ = http.Client{}
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var matched bool
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				result := gosec.MatchCompLit(n, ctx, "net/http.Client")
				if result != nil {
					matched = true
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(matched).To(BeTrue())
		})

		It("should return nil for non-matching type", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			import "net/http"
			func main() {
				_ = http.Client{}
			}
			`)
			ctx := pkg.CreateContext("main.go")
			matched := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				result := gosec.MatchCompLit(n, ctx, "net/http.Server")
				if result != nil {
					matched = true
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(matched).To(BeFalse())
		})
	})

	Context("when getting call objects", func() {
		It("should get call object for identifier", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func test() {}
			func main() {
				test()
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var foundObj bool
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				callExpr, obj := gosec.GetCallObject(n, ctx)
				if callExpr != nil && obj != nil {
					foundObj = true
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundObj).To(BeTrue())
		})

		It("should get call object for selector expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			import "fmt"
			func main() {
				fmt.Println("test")
			}
			`)
			ctx := pkg.CreateContext("main.go")
			var foundObj bool
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				callExpr, obj := gosec.GetCallObject(n, ctx)
				if callExpr != nil && obj != nil {
					foundObj = true
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundObj).To(BeTrue())
		})

		It("should return nil for non-call expression", func() {
			pkg := testutils.NewTestPackage()
			defer pkg.Close()
			pkg.AddFile("main.go", `
			package main
			func main() {
				x := 42
				_ = x
			}
			`)
			ctx := pkg.CreateContext("main.go")
			foundNil := false
			visitor := testutils.NewMockVisitor()
			visitor.Context = ctx
			visitor.Callback = func(n ast.Node, ctx *gosec.Context) bool {
				if _, ok := n.(*ast.BasicLit); ok {
					callExpr, obj := gosec.GetCallObject(n, ctx)
					if callExpr == nil && obj == nil {
						foundNil = true
					}
				}
				return true
			}
			ast.Walk(visitor, ctx.Root)
			Expect(foundNil).To(BeTrue())
		})
	})
})
