package ssautil_test

import (
	"os"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/ctrlflow"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/internal/ssautil"
)

func buildSSAFromSource(source string) *buildssa.SSA {
	GinkgoHelper()

	tempDir, err := os.MkdirTemp("", "ssautil-cache-test")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	err = os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module testcache\n\ngo 1.25\n"), 0o600)
	Expect(err).NotTo(HaveOccurred())

	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(source), 0o600)
	Expect(err).NotTo(HaveOccurred())

	pkgs, err := packages.Load(&packages.Config{Mode: gosec.LoadMode, Dir: tempDir}, ".")
	Expect(err).NotTo(HaveOccurred())
	Expect(pkgs).NotTo(BeEmpty())
	Expect(pkgs[0].Errors).To(BeEmpty())

	pass := &analysis.Pass{
		Fset:       pkgs[0].Fset,
		Files:      pkgs[0].Syntax,
		Pkg:        pkgs[0].Types,
		TypesInfo:  pkgs[0].TypesInfo,
		TypesSizes: pkgs[0].TypesSizes,
		ResultOf:   make(map[*analysis.Analyzer]any),
		Report:     func(analysis.Diagnostic) {},
	}

	pass.Analyzer = inspect.Analyzer
	iRes, err := inspect.Analyzer.Run(pass)
	Expect(err).NotTo(HaveOccurred())
	pass.ResultOf[inspect.Analyzer] = iRes

	pass.Analyzer = ctrlflow.Analyzer
	cfRes, err := ctrlflow.Analyzer.Run(pass)
	Expect(err).NotTo(HaveOccurred())
	pass.ResultOf[ctrlflow.Analyzer] = cfRes

	res, err := buildssa.Analyzer.Run(pass)
	Expect(err).NotTo(HaveOccurred())

	ssaResult, ok := res.(*buildssa.SSA)
	Expect(ok).To(BeTrue())
	Expect(ssaResult).NotTo(BeNil())
	Expect(ssaResult.SrcFuncs).NotTo(BeEmpty())

	return ssaResult
}

var _ = Describe("PackageAnalysisCache", func() {
	It("returns nil callgraph for nil receiver", func() {
		var cache *ssautil.PackageAnalysisCache
		Expect(cache.CallGraph()).To(BeNil())
	})

	It("returns nil callgraph when SSA is nil", func() {
		cache := ssautil.NewPackageAnalysisCache(nil)
		Expect(cache.CallGraph()).To(BeNil())
	})

	It("returns nil callgraph when source functions are empty", func() {
		cache := ssautil.NewPackageAnalysisCache(&buildssa.SSA{})
		Expect(cache.CallGraph()).To(BeNil())
	})

	It("returns nil callgraph when first source function is nil", func() {
		cache := ssautil.NewPackageAnalysisCache(&buildssa.SSA{SrcFuncs: []*ssa.Function{nil}})
		Expect(cache.CallGraph()).To(BeNil())
	})

	It("builds and memoizes callgraph for valid SSA", func() {
		ssaResult := buildSSAFromSource(`package main

func helper() {}

func main() {
	helper()
}`)
		cache := ssautil.NewPackageAnalysisCache(ssaResult)

		first := cache.CallGraph()
		Expect(first).NotTo(BeNil())

		second := cache.CallGraph()
		Expect(second).To(BeIdenticalTo(first))
	})

	It("is concurrency-safe and initializes once", func() {
		ssaResult := buildSSAFromSource(`package main

func helper() {}

func main() {
	helper()
}`)
		cache := ssautil.NewPackageAnalysisCache(ssaResult)

		const workers = 12
		graphs := make([]any, workers)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				graphs[idx] = cache.CallGraph()
			}(i)
		}
		wg.Wait()

		Expect(graphs[0]).NotTo(BeNil())
		for i := 1; i < workers; i++ {
			Expect(graphs[i]).To(BeIdenticalTo(graphs[0]))
		}
	})
})
