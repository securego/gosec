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

// Package core holds the central scanning logic used by GAS
package core

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path"
	"reflect"
	"strings"
)

// ImportInfo is used to track aliased and initialization only imports.
type ImportInfo struct {
	Imported map[string]string
	Aliased  map[string]string
	InitOnly map[string]bool
}

func NewImportInfo() *ImportInfo {
	return &ImportInfo{
		make(map[string]string),
		make(map[string]string),
		make(map[string]bool),
	}
}

// The FileInfo stored a parsed file along with its absolute file path
type FileInfo struct {
	FilePath string
	File     *ast.File
}

// The Context is populated with data parsed from the source code as it is scanned.
// It is passed through to all rule functions as they are called. Rules may use
// this data in conjunction withe the encoutered AST node.
type Context struct {
	FileSet  *token.FileSet
	Comments []ast.CommentMap
	Info     *types.Info
	Pkg      *types.Package
	Files    []FileInfo
	Config   map[string]interface{}
	Imports  *ImportInfo
}

// The Rule interface used by all rules supported by GAS.
type Rule interface {
	Match(ast.Node, *Context) (*Issue, error)
}

// A RuleSet maps lists of rules to the type of AST node they should be run on.
// The anaylzer will only invoke rules contained in the list associated with the
// type of AST node it is currently visiting.
type RuleSet map[reflect.Type][]Rule

// Metrics used when reporting information about a scanning run.
type Metrics struct {
	NumFiles int `json:"files"`
	NumLines int `json:"lines"`
	NumNosec int `json:"nosec"`
	NumFound int `json:"found"`
}

// The Analyzer object is the main object of GAS. It has methods traverse an AST
// and invoke the correct checking rules as on each node as required.
type Analyzer struct {
	ignoreNosec bool
	ruleset     RuleSet
	context     *Context
	logger      *log.Logger
	Issues      []*Issue `json:"issues"`
	Stats       *Metrics `json:"metrics"`
}

// NewAnalyzer builds a new anaylzer.
func NewAnalyzer(conf map[string]interface{}, logger *log.Logger) Analyzer {
	if logger == nil {
		logger = log.New(os.Stdout, "[gas]", 0)
	}
	a := Analyzer{
		ignoreNosec: conf["ignoreNosec"].(bool),
		ruleset:     make(RuleSet),
		context:     &Context{nil, nil, nil, nil, nil, nil, nil},
		logger:      logger,
		Issues:      make([]*Issue, 0, 16),
		Stats:       &Metrics{0, 0, 0, 0},
	}

	// TODO(tkelsey): use the inc/exc lists

	return a
}

func (gas *Analyzer) analyze() {
	for _, file := range gas.context.Files {
		gas.logger.Printf("Analyzing file %s ...", file.FilePath)
		ast.Walk(gas, file.File)
		gas.Stats.NumFiles++
	}
}

func (gas *Analyzer) resolveTypes(pkg string) (err error) {
	gas.context.Info = &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
		Implicits:  make(map[ast.Node]types.Object),
	}

	gas.logger.Printf("Resolving types of package %s ...", pkg)

	conf := types.Config{Importer: importer.Default()}
	var files []*ast.File
	for _, file := range gas.context.Files {
		files = append(files, file.File)
	}
	gas.context.Pkg, err = conf.Check(pkg, gas.context.FileSet, files, gas.context.Info)
	if err != nil {
		return err
	}

	gas.context.Imports = NewImportInfo()
	for _, pkg := range gas.context.Pkg.Imports() {
		gas.context.Imports.Imported[pkg.Path()] = pkg.Name()
	}

	return nil
}

func (gas *Analyzer) parsePkg(pkg string, filenames ...string) error {
	mode := parser.ParseComments
	gas.context.FileSet = token.NewFileSet()
	for _, filename := range filenames {
		gas.logger.Printf("Parsing file %s ...", filename)
		file, err := parser.ParseFile(gas.context.FileSet, filename, nil, mode)
		if err != nil {
			return err
		}
		fileInfo := FileInfo{filename, file}
		gas.context.Files = append(gas.context.Files, fileInfo)
	}

	for _, file := range gas.context.Files {
		commentMap := ast.NewCommentMap(gas.context.FileSet, file.File, file.File.Comments)
		gas.context.Comments = append(gas.context.Comments, commentMap)
	}
	return nil
}

func (gas *Analyzer) parseFile(filename string, source interface{}) error {
	mode := parser.ParseComments
	gas.context.FileSet = token.NewFileSet()
	gas.logger.Printf("Parsing the file %s\n", filename)
	file, err := parser.ParseFile(gas.context.FileSet, filename, source, mode)
	if err != nil {
		return err
	}
	fileInfo := FileInfo{filename, file}
	gas.context.Files = append(gas.context.Files, fileInfo)
	commentMap := ast.NewCommentMap(gas.context.FileSet, file, file.Comments)
	gas.context.Comments = append(gas.context.Comments, commentMap)
	return err
}

// AddRule adds a rule into a rule set list mapped to the given AST node's type.
// The node is only needed for its type and is not otherwise used.
func (gas *Analyzer) AddRule(r Rule, nodes []ast.Node) {
	for _, n := range nodes {
		t := reflect.TypeOf(n)
		if val, ok := gas.ruleset[t]; ok {
			gas.ruleset[t] = append(val, r)
		} else {
			gas.ruleset[t] = []Rule{r}
		}
	}
}

// ProcessPkg reads in all files of a package, convert them to an AST and traverse it.
// Rule methods added with AddRule will be invoked as necessary.
func (gas *Analyzer) ProcessPkg(pkg string, filenames ...string) error {
	err := gas.parsePkg(pkg, filenames...)
	if err != nil {
		return err
	}

	err = gas.resolveTypes(pkg)
	if err != nil {
		return err
	}

	gas.analyze()

	fun := func(f *token.File) bool {
		gas.Stats.NumLines += f.LineCount()
		return true
	}
	gas.context.FileSet.Iterate(fun)
	return nil
}

// ProcessSource will convert a source code string into an AST and traverse it.
// Rule methods added with AddRule will be invoked as necessary. The string is
// identified by the filename given but no file IO will be done.
func (gas *Analyzer) ProcessSource(pkg string, filename string, source string) error {
	err := gas.parseFile(filename, source)
	if err != nil {
		return err
	}
	err = gas.resolveTypes(pkg)
	if err != nil {
		return err
	}
	gas.analyze()

	fun := func(f *token.File) bool {
		gas.Stats.NumLines += f.LineCount()
		return true
	}
	gas.context.FileSet.Iterate(fun)
	return nil
}

// ignore a node (and sub-tree) if it is tagged with a "#nosec" comment
func (gas *Analyzer) ignore(n ast.Node) bool {
	for _, commentMap := range gas.context.Comments {
		if groups, ok := commentMap[n]; ok && !gas.ignoreNosec {
			for _, group := range groups {
				if strings.Contains(group.Text(), "#nosec") {
					gas.Stats.NumNosec++
					return true
				}
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
		if imported, ok := n.(*ast.ImportSpec); ok {
			path := strings.Trim(imported.Path.Value, `"`)
			if imported.Name != nil {
				if imported.Name.Name == "_" {
					// Initialization import
					gas.context.Imports.InitOnly[path] = true
				} else {
					// Aliased import
					gas.context.Imports.Aliased[path] = imported.Name.Name
				}
			}
			// unsafe is not included in Package.Imports()
			if path == "unsafe" {
				gas.context.Imports.Imported[path] = path
			}
		}

		if val, ok := gas.ruleset[reflect.TypeOf(n)]; ok {
			for _, rule := range val {
				ret, err := rule.Match(n, gas.context)
				if err != nil {
					file, line := GetLocation(n, gas.context)
					file = path.Base(file)
					gas.logger.Printf("Rule error: %v => %s (%s:%d)\n", reflect.TypeOf(rule), err, file, line)
				}
				if ret != nil {
					gas.Issues = append(gas.Issues, ret)
					gas.Stats.NumFound++
				}
			}
		}
		return gas
	}
	return nil
}
