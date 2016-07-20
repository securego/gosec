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

func (f *filelist) Contains(path string) bool {
	// Ignore dot files
	_, filename := filepath.Split(path)
	if strings.HasPrefix(filename, ".") {
		return true
	}
	for _, pattern := range *f {
		// Match entire path
		if rv, err := filepath.Match(pattern, path); rv && err == nil {
			return true
		}
	}
	return false
}
