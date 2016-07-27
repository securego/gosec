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
	"os"
	"path"
	"path/filepath"
	"strings"
)

type filelist []string

func (f *filelist) String() string {
	return strings.Join([]string(*f), ", ")
}

func (f *filelist) Set(val string) error {
	*f = append(*f, val)
	return nil
}

func (f *filelist) Contains(pathname string) bool {

	// Ignore dot files
	_, filename := filepath.Split(pathname)
	if strings.HasPrefix(filename, ".") {
		return true
	}

	cwd, _ := os.Getwd()
	abs, _ := filepath.Abs(pathname)

	for _, pattern := range *f {

		// Also check working directory
		rel := path.Join(cwd, pattern)

		// Match pattern directly
		if matched, _ := filepath.Match(pattern, pathname); matched {
			return true
		}
		// Also check pattern relative to working directory
		if matched, _ := filepath.Match(rel, pathname); matched {
			return true
		}

		// Finally try absolute path
		st, e := os.Stat(rel)
		if !os.IsNotExist(e) && st.IsDir() && strings.HasPrefix(abs, rel) {
			return true
		}

	}
	return false
}
