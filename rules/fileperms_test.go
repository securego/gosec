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

package rules

import (
	"testing"

	gas "github.com/HewlettPackard/gas/core"
)

func TestChmod(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewChmodPerms())

	issues := gasTestRunner(`
		package main
        	import "os"
		func main() {
			os.Chmod("/tmp/somefile", 0777)
			os.Chmod("/tmp/someotherfile", 0600)
		}`, analyzer)

	checkTestResults(t, issues, 1, "Expect chmod permissions")
}

func TestMkdir(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewMkdirPerms())

	issues := gasTestRunner(`
		package main
		import "os"
		func main() {
			os.Mkdir("/tmp/mydir", 0777)
			os.Mkdir("/tmp/mydir", 0600)
			os.MkdirAll("/tmp/mydir/mysubidr", 0775)
		}`, analyzer)

	checkTestResults(t, issues, 2, "Expect directory permissions")
}
