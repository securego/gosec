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

type set map[string]bool

type calls struct {
	matchAny  bool
	functions set
}

/// CallList is used to check for usage of specific packages
/// and functions.
type CallList map[string]*calls

/// NewCallList creates a new empty CallList
func NewCallList() CallList {
	return make(CallList)
}

/// NewCallListFor createse a call list using the package path
func NewCallListFor(pkg string, funcs ...string) CallList {
	c := NewCallList()
	if len(funcs) == 0 {
		c[pkg] = &calls{true, make(set)}
	} else {
		for _, fn := range funcs {
			c.Add(pkg, fn)
		}
	}
	return c
}

/// Add a new package and function to the call list
func (c CallList) Add(pkg, fn string) {
	if cl, ok := c[pkg]; ok {
		if cl.matchAny {
			cl.matchAny = false
		}
	} else {
		c[pkg] = &calls{false, make(set)}
	}
	c[pkg].functions[fn] = true
}

/// Contains returns true if the package and function are
/// members of this call list.
func (c CallList) Contains(pkg, fn string) bool {
	if funcs, ok := c[pkg]; ok {
		_, ok = funcs.functions[fn]
		return ok || funcs.matchAny
	}
	return false
}
