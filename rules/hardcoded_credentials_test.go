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

func TestHardcoded(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))

	issues := gasTestRunner(
		`
		package samples

		import "fmt"

		func main() {
			username := "admin"
			password := "admin"
			fmt.Println("Doing something with: ", username, password)
		}`, analyzer)

	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}

func TestHardcodedGlobalVar(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))

	issues := gasTestRunner(`
		package samples

		import "fmt"

		var password = "admin"

		func main() {
			username := "admin"
			fmt.Println("Doing something with: ", username, password)
		}`, analyzer)

	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}

func TestHardcodedConstant(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))

	issues := gasTestRunner(`
		package samples

		import "fmt"

		const password = "secret"

		func main() {
			username := "admin"
			fmt.Println("Doing something with: ", username, password)
		}`, analyzer)

	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}

func TestHardcodedConstantMulti(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))

	issues := gasTestRunner(`
		package samples

		import "fmt"

		const username, password = "secret"

		func main() {
			fmt.Println("Doing something with: ", username, password)
		}`, analyzer)

	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}

func TestHardecodedVarsNotAssigned(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))
	issues := gasTestRunner(`
		package main 
		var password string
		func init() {
			password = "this is a secret string"
		}`, analyzer)
	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}

func TestHardcodedConstInteger(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))
	issues := gasTestRunner(`
		package main

		const (
			ATNStateSomethingElse = 1
			ATNStateTokenStart = 42
		)
		func main() {
			println(ATNStateTokenStart)
		}`, analyzer)
	checkTestResults(t, issues, 0, "Potential hardcoded credentials")
}

func TestHardcodedConstString(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewHardcodedCredentials(config))
	issues := gasTestRunner(`
		package main

		const (
			ATNStateTokenStart = "foo bar"
		)
		func main() {
			println(ATNStateTokenStart)
		}`, analyzer)
	checkTestResults(t, issues, 1, "Potential hardcoded credentials")
}
