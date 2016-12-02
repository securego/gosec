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
	"strings"

	"github.com/ryanuber/go-glob"
)

// fileList uses a map for patterns to ensure each pattern only
// appears once
type fileList struct {
	patterns map[string]struct{}
}

func newFileList(paths ...string) *fileList {
	f := &fileList{
		patterns: make(map[string]struct{}),
	}
	for _, p := range paths {
		f.patterns[p] = struct{}{}
	}
	return f
}

func (f *fileList) String() string {
	ps := make([]string, 0, len(f.patterns))
	for p := range f.patterns {
		ps = append(ps, p)
	}
	return strings.Join(ps, ", ")
}

func (f *fileList) Set(path string) error {
	if path == "" {
		// don't bother adding the empty path
		return nil
	}
	f.patterns[path] = struct{}{}
	return nil
}

func (f fileList) Contains(path string) bool {
	for p := range f.patterns {
		if glob.Glob(p, path) {
			if logger != nil {
				logger.Printf("skipping: %s\n", path)
			}
			return true
		}
	}
	//log.Printf("including: %s\n", path)
	return false
}

/*
func (f fileList) Dump() {
	for k, _ := range f.paths {
		println(k)
	}
}
*/
