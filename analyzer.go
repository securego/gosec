// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gas holds the central scanning logic used by GAS
package gas

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path"
	"reflect"
	"strings"

	"golang.org/x/tools/go/loader"
)

// The Context is populated with data parsed from the source code as it is scanned.
// It is passed through to all rule functions as they are called. Rules may use
// this data in conjunction withe the encoutered AST node.
type Context struct {
	FileSet  *token.FileSet
	Comments ast.CommentMap
	Info     *types.Info
	Pkg      *types.Package
	Root     *ast.File
	Config   map[string]interface{}
	Imports  *ImportTracker
}

// Metrics used when reporting information about a scanning run.
type Metrics struct {
	NumFiles int `json:"files"`
	NumLines int `json:"lines"`
	NumNosec int `json:"nosec"`
	NumFound int `json:"found"`
}

// Analyzer object is the main object of GAS. It has methods traverse an AST
// and invoke the correct checking rules as on each node as required.
type Analyzer struct {
	ignoreNosec   bool
	ruleset       RuleSet
	context       *Context
	config        Config
	logger        *log.Logger
	issues        []*Issue
	stats         *Metrics
	builtPkgCache map[string]*buildPackageCacheEntry
}

type buildPackageCacheEntry struct {
	info *loader.PackageInfo
	fset *token.FileSet
}

// NewAnalyzer builds a new anaylzer.
func NewAnalyzer(conf Config, logger *log.Logger) *Analyzer {
	ignoreNoSec := false
	if setting, err := conf.GetGlobal("nosec"); err == nil {
		ignoreNoSec = setting == "true" || setting == "enabled"
	}
	if logger == nil {
		logger = log.New(os.Stderr, "[gas]", log.LstdFlags)
	}
	return &Analyzer{
		ignoreNosec:   ignoreNoSec,
		ruleset:       make(RuleSet),
		context:       &Context{},
		config:        conf,
		logger:        logger,
		issues:        make([]*Issue, 0, 16),
		stats:         &Metrics{},
		builtPkgCache: make(map[string]*buildPackageCacheEntry),
	}
}

// LoadRules instantiates all the rules to be used when analyzing source
// packages
func (gas *Analyzer) LoadRules(ruleDefinitions ...RuleBuilder) {
	for _, builder := range ruleDefinitions {
		r, nodes := builder(gas.config)
		gas.ruleset.Register(r, nodes...)
	}
}

// Process kicks off the analysis process for a given package
func (gas *Analyzer) Process(packagePath string) error {
	var packages []*loader.PackageInfo
	var fset *token.FileSet

	basePackage, err := build.Default.ImportDir(packagePath, build.ImportComment)
	if err != nil {
		return err
	}

	packageConfig := loader.Config{Build: &build.Default, ParserMode: parser.ParseComments}
	var packageFiles []string
	for _, filename := range basePackage.GoFiles {
		packageFiles = append(packageFiles, path.Join(packagePath, filename))
	}

	packageConfig.CreateFromFilenames(basePackage.Name, packageFiles...)

	pkgCachePath := packagePath
	// Calculate an absolute import path because the cache is keyed by the absolute import path
	if build.IsLocalImport(pkgCachePath) {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}

		pkg, err := build.Default.Import(packagePath, wd, build.ImportComment)
		if err != nil {
			return err
		}
		pkgCachePath = pkg.ImportPath
	}

	if gas.builtPkgCache[pkgCachePath] != nil {
		entry := gas.builtPkgCache[pkgCachePath]
		packages = append(packages, entry.info)
		fset = entry.fset
	} else {
		builtPackage, err := packageConfig.Load()
		if err != nil {
			return err
		}

		packages = builtPackage.Created
		fset = builtPackage.Fset

		// Cache built packages
		for details, pkg := range builtPackage.AllPackages {
			if !details.Complete() {
				continue
			}
			entry := buildPackageCacheEntry{
				info: pkg,
				fset: builtPackage.Fset,
			}
			gas.builtPkgCache[pkg.Pkg.Path()] = &entry
		}
	}

	for _, pkg := range packages {
		gas.logger.Println("Checking package:", pkg.String())
		for _, file := range pkg.Files {
			gas.logger.Println("Checking file:", fset.File(file.Pos()).Name())
			gas.context.FileSet = fset
			gas.context.Config = gas.config
			gas.context.Comments = ast.NewCommentMap(gas.context.FileSet, file, file.Comments)
			gas.context.Root = file
			gas.context.Info = &pkg.Info
			gas.context.Pkg = pkg.Pkg
			gas.context.Imports = NewImportTracker()
			gas.context.Imports.TrackPackages(gas.context.Pkg.Imports()...)
			ast.Walk(gas, file)
			gas.stats.NumFiles++
			gas.stats.NumLines += fset.File(file.Pos()).LineCount()
		}
	}
	return nil
}

// ignore a node (and sub-tree) if it is tagged with a "#nosec" comment
func (gas *Analyzer) ignore(n ast.Node) bool {
	if groups, ok := gas.context.Comments[n]; ok && !gas.ignoreNosec {
		for _, group := range groups {
			if strings.Contains(group.Text(), "#nosec") {
				gas.stats.NumNosec++
				return true
			}
		}
	}
	return false
}

// Visit runs the GAS visitor logic over an AST created by parsing go code.
// Rule methods added with AddRule will be invoked as necessary.
func (gas *Analyzer) Visit(n ast.Node) ast.Visitor {
	if !gas.ignore(n) {

		// Track aliased and initialization imports
		gas.context.Imports.TrackImport(n)

		for _, rule := range gas.ruleset.RegisteredFor(n) {
			issue, err := rule.Match(n, gas.context)
			if err != nil {
				file, line := GetLocation(n, gas.context)
				file = path.Base(file)
				gas.logger.Printf("Rule error: %v => %s (%s:%d)\n", reflect.TypeOf(rule), err, file, line)
			}
			if issue != nil {
				gas.issues = append(gas.issues, issue)
				gas.stats.NumFound++
			}
		}
		return gas
	}
	return nil
}

// Report returns the current issues discovered and the metrics about the scan
func (gas *Analyzer) Report() ([]*Issue, *Metrics) {
	return gas.issues, gas.stats
}

// Reset clears state such as context, issues and metrics from the configured analyzer
func (gas *Analyzer) Reset() {
	gas.context = &Context{}
	gas.issues = make([]*Issue, 0, 16)
	gas.stats = &Metrics{}
}
