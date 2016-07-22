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

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type command func(args ...string)
type utilities struct {
	commands map[string]command
	call     []string
}

// Custom commands / utilities to run instead of default analyzer
func newUtils() *utilities {
	utils := make(map[string]command)
	utils["dump"] = dumpAst
	return &utilities{utils, make([]string, 0)}
}

func (u *utilities) String() string {
	i := 0
	keys := make([]string, len(u.commands))
	for k := range u.commands {
		keys[i] = k
		i++
	}
	return strings.Join(keys, ", ")
}

func (u *utilities) Set(opt string) error {
	if _, ok := u.commands[opt]; !ok {
		return fmt.Errorf("valid tools are: %s", u.String())

	}
	u.call = append(u.call, opt)
	return nil
}

func (u *utilities) run(args ...string) {
	for _, util := range u.call {
		if cmd, ok := u.commands[util]; ok {
			cmd(args...)
		}
	}
}

func dumpAst(files ...string) {
	for _, arg := range files {
		// Ensure file exists and not a directory
		st, e := os.Stat(arg)
		if e != nil {
			fmt.Fprintf(os.Stderr, "Skipping: %s - %s\n", arg, e)
			continue
		}
		if st.IsDir() {
			fmt.Fprintf(os.Stderr, "Skipping: %s - directory\n", arg)
			continue
		}

		// Create the AST by parsing src.
		fset := token.NewFileSet() // positions are relative to fset
		f, err := parser.ParseFile(fset, arg, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse file %s\n", err)
			continue
		}

		// Print the AST.
		ast.Print(fset, f)
	}
}
