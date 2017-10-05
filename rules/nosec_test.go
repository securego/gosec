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
	analyzer.AddRule(NewSubproc("G001", config))

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
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
		"os" 
		"os/exec"
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
	analyzer.AddRule(NewSubproc("G001", config))

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

func TestNosecExcludeOne(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH")) // #exclude !G001
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 0, "None")
}

func TestNosecExcludeOneNoMatch(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH")) // #exclude !G002
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with variable.")
}

func TestNosecExcludeOneMatchNextLine(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("FOO")) // #exclude !G001
		cmd = exec.Command("sh", "-c", os.Getenv("BAR")) 
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with variable.")
}

func TestNosecBlockExcludeOne(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
		"os" 
		"os/exec"
	)

	func main() {
			// #exclude !G001
			if true {
				cmd := exec.Command("sh", "-c", os.Getenv("BLAH"))
				cmd.Run()
			}
	}`, analyzer)

	checkTestResults(t, issues, 0, "None")
}

func TestNosecBlockExcludeOneWithComment(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
		"os" 
		"os/exec"
	)

	func main() {
			// #exclude !G001(This rule is bogus)
			if true {
				cmd := exec.Command("sh", "-c", os.Getenv("BLAH"))
				cmd.Run()
			}
	}`, analyzer)

	checkTestResults(t, issues, 0, "None")
}

func TestNosecBlockExcludeOneNoMatch(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))

	issues := gasTestRunner(
		`package main
		import (
		"os" 
		"os/exec"
	)

	func main() {
			// #exclude !G002
			if true {
				cmd := exec.Command("sh", "-c", os.Getenv("BLAH"))
				cmd.Run()
			}
	}`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with variable.")
}

func TestNosecExcludeTwoNoMatch(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))
	analyzer.AddRule(NewWeakRandCheck("G002", config))

	issues := gasTestRunner(
		`package main
		import (
			"math/rand"
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH"), string(rand.Int())) // #exclude !G003 !G004
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 2, "")
}

func TestNosecExcludeTwoOneMatch(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))
	analyzer.AddRule(NewWeakRandCheck("G002", config))

	issues := gasTestRunner(
		`package main
		import (
			"math/rand"
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH"), string(rand.Int())) // #exclude !G001 !G004
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 1, "Use of weak random number generator")
}

func TestNosecExcludeTwoBothMatch(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))
	analyzer.AddRule(NewWeakRandCheck("G002", config))

	issues := gasTestRunner(
		`package main
		import (
			"math/rand"
			"os"
			"os/exec"
		)

	func main() {
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH"), string(rand.Int())) // #exclude !G001 !G002
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 0, "No issues")
}

func TestNosecExcludeTwoWithComments(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc("G001", config))
	analyzer.AddRule(NewWeakRandCheck("G002", config))

	issues := gasTestRunner(
		`package main
		import (
			"math/rand"
			"os"
			"os/exec"
		)

	func main() {
		// #exclude !G001(The env var is trusted) !G002(Unimportant random number)
		cmd := exec.Command("sh", "-c", os.Getenv("BLAH"), string(rand.Int()))
		cmd.Run()
	}`, analyzer)

	checkTestResults(t, issues, 0, "No issues")
}
