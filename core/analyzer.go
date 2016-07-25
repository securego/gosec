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

package core

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"reflect"
	"strings"
)

type Context struct {
	FileSet  *token.FileSet
	Comments ast.CommentMap
	Info     *types.Info
	Pkg      *types.Package
}

type Rule interface {
	Match(ast.Node, *Context) (*Issue, error)
}

type RuleSet map[reflect.Type][]Rule

type Metrics struct {
	NumFiles int
	NumLines int
	NumNosec int
	NumFound int
}

type Analyzer struct {
	annotations bool
	ruleset     RuleSet
	context     Context
	logger      *log.Logger
	Issues      []Issue
	Stats       Metrics
}

func NewAnalyzer(annotations bool, logger *log.Logger) Analyzer {
	if logger == nil {
		logger = log.New(os.Stdout, "[gas]", 0)
	}
	return Analyzer{
		annotations: annotations,
		ruleset:     make(RuleSet),
		Issues:      make([]Issue, 0),
		context:     Context{token.NewFileSet(), nil, nil, nil},
		logger:      logger,
	}
}

func (gas *Analyzer) process(filename string, source interface{}) error {
	mode := parser.ParseComments
	root, err := parser.ParseFile(gas.context.FileSet, filename, source, mode)
	if err == nil {
		gas.context.Comments = ast.NewCommentMap(gas.context.FileSet, root, root.Comments)

		// here we get type info
		gas.context.Info = &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
			Defs:  make(map[*ast.Ident]types.Object),
			Uses:  make(map[*ast.Ident]types.Object),
		}

		conf := types.Config{Importer: importer.Default()}
		gas.context.Pkg, _ = conf.Check("pkg", gas.context.FileSet, []*ast.File{root}, gas.context.Info)
		if err != nil {
			gas.logger.Println("failed to check imports")
			return err
		}

		ast.Walk(gas, root)
		gas.Stats.NumFiles++
	}
	return err
}

func (gas *Analyzer) AddRule(r Rule, n ast.Node) {
	t := reflect.TypeOf(n)
	if val, ok := gas.ruleset[t]; ok {
		gas.ruleset[t] = append(val, r)
	} else {
		gas.ruleset[t] = []Rule{r}
	}
}

func (gas *Analyzer) Process(filename string) error {
	err := gas.process(filename, nil)
	fun := func(f *token.File) bool {
		gas.Stats.NumLines += f.LineCount()
		return true
	}
	gas.context.FileSet.Iterate(fun)
	return err
}

func (gas *Analyzer) ProcessSource(filename string, source string) error {
	err := gas.process(filename, source)
	fun := func(f *token.File) bool {
		gas.Stats.NumLines += f.LineCount()
		return true
	}
	gas.context.FileSet.Iterate(fun)
	return err
}

func (gas *Analyzer) Ignore(n ast.Node) bool {
	if groups, ok := gas.context.Comments[n]; ok {
		for _, group := range groups {
			if strings.Contains(group.Text(), "nosec") {
				gas.Stats.NumNosec++
				return true
			}
		}
	}
	return false
}

func (gas *Analyzer) Visit(n ast.Node) ast.Visitor {
	if !gas.annotations || gas.Ignore(n) {
		if val, ok := gas.ruleset[reflect.TypeOf(n)]; ok {
			for _, rule := range val {
				ret, err := rule.Match(n, &gas.context)
				if err != nil {
					// will want to give more info than this ...
					gas.logger.Println("internal error running rule:", err)
				}
				if ret != nil {
					gas.Issues = append(gas.Issues, *ret)
					gas.Stats.NumFound++
				}
			}
		}
	}
	return gas
}
