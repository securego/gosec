package gas_test

import (
	"go/ast"

	"github.com/GoASTScanner/gas"
	"github.com/GoASTScanner/gas/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("call list", func() {
	var (
		calls gas.CallList
	)
	BeforeEach(func() {
		calls = gas.NewCallList()
	})

	It("should not return any matches when empty", func() {
		Expect(calls.Contains("foo", "bar")).Should(BeFalse())
	})

	It("should be possible to add a single call", func() {
		Expect(calls).Should(HaveLen(0))
		calls.Add("foo", "bar")
		Expect(calls).Should(HaveLen(1))

		expected := make(map[string]bool)
		expected["bar"] = true
		actual := map[string]bool(calls["foo"])
		Expect(actual).Should(Equal(expected))
	})

	It("should be possible to add multiple calls at once", func() {
		Expect(calls).Should(HaveLen(0))
		calls.AddAll("fmt", "Sprint", "Sprintf", "Printf", "Println")

		expected := map[string]bool{
			"Sprint":  true,
			"Sprintf": true,
			"Printf":  true,
			"Println": true,
		}
		actual := map[string]bool(calls["fmt"])
		Expect(actual).Should(Equal(expected))
	})

	It("should not return a match if none are present", func() {
		calls.Add("ioutil", "Copy")
		Expect(calls.Contains("fmt", "Println")).Should(BeFalse())
	})

	It("should match a call based on selector and ident", func() {
		calls.Add("ioutil", "Copy")
		Expect(calls.Contains("ioutil", "Copy")).Should(BeTrue())
	})

	It("should match a call expression", func() {

		// Create file to be scanned
		pkg := testutils.NewTestPackage()
		defer pkg.Close()
		pkg.AddFile("md5.go", testutils.SampleCodeG401[0].Code)

		ctx := pkg.CreateContext("md5.go")

		// Search for md5.New()
		calls.Add("md5", "New")

		// Stub out visitor and count number of matched call expr
		matched := 0
		v := testutils.NewMockVisitor()
		v.Context = ctx
		v.Callback = func(n ast.Node, ctx *gas.Context) bool {
			if _, ok := n.(*ast.CallExpr); ok && calls.ContainsCallExpr(n, ctx) != nil {
				matched++
			}
			return true
		}
		ast.Walk(v, ctx.Root)
		Expect(matched).Should(Equal(1))

	})

})
