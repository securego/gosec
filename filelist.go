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
	"os"
	"path/filepath"
	"strings"
)

type filelist struct {
	paths map[string]bool
	globs []string
}

func newFileList(paths ...string) *filelist {

	f := &filelist{
		make(map[string]bool),
		make([]string, 0),
	}

	for _, path := range paths {
		if e := f.Set(path); e != nil {
			// #nosec
			fmt.Fprintf(os.Stderr, "Unable to add %s to filelist: %s\n", path, e)
		}
	}
	return f
}

func (f *filelist) String() string {
	return strings.Join(f.globs, ", ")
}

func (f *filelist) Set(path string) error {
	f.globs = append(f.globs, path)
	matches, e := filepath.Glob(path)
	if e != nil {
		return e
	}
	for _, each := range matches {
		abs, e := filepath.Abs(each)
		if e != nil {
			return e
		}
		f.paths[abs] = true
	}
	return nil
}

func (f filelist) Contains(path string) bool {
	_, present := f.paths[path]
	return present
}

/*
func (f filelist) Dump() {
	for k, _ := range f.paths {
		println(k)
	}
}
*/
