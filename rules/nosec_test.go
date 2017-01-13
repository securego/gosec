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

	gas "github.com/GoASTScanner/gas/core"
)

func TestNosec(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(
		`package main
		import (
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH")) // #nosec
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 0, "None")
}

func TestNosecBlock(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(
		`package main
		import (
		"os" 
		"os/exect"
	)

	func main() {
			// #nosec
			if true {
				cmd := exec.Command("sh", "-c", os.Getenv("BLAH"))
				cmd.Run()
			}
	}`, analyzer)

	checkTestResults(t, issues, 0, "None")
}

func TestNosecIgnore(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": true}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(
		`package main

		import (
			"os"
			"os/exec"
		)

		func main() {
			cmd := exec.Command("sh", "-c", os.Args[1]) // #nosec
			cmd.Run()
		}`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with variable.")
}
