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

func TestSubprocess(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(`
    package main

    import (
    	"log"
    	"os/exec"
    )

    func main() {
			val := "/bin/" + "sleep"
    	cmd := exec.Command(val, "5")
    	err := cmd.Start()
    	if err != nil {
    		log.Fatal(err)
    	}
    	log.Printf("Waiting for command to finish...")
    	err = cmd.Wait()
    	log.Printf("Command finished with error: %v", err)
    }`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching should be audited.")
}

func TestSubprocessVar(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(`
    package main

    import (
    	"log"
    	"os/exec"
    )

    func main() {
      run := "sleep" + someFunc()
    	cmd := exec.Command(run, "5")
    	err := cmd.Start()
    	if err != nil {
    		log.Fatal(err)
    	}
    	log.Printf("Waiting for command to finish...")
    	err = cmd.Wait()
    	log.Printf("Command finished with error: %v", err)
    }`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with variable.")
}

func TestSubprocessPath(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(`
    package main

    import (
    	"log"
    	"os/exec"
    )

    func main() {
    	cmd := exec.Command("sleep", "5")
    	err := cmd.Start()
    	if err != nil {
    		log.Fatal(err)
    	}
    	log.Printf("Waiting for command to finish...")
    	err = cmd.Wait()
    	log.Printf("Command finished with error: %v", err)
    }`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching with partial path.")
}

func TestSubprocessSyscall(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSubproc(config))

	issues := gasTestRunner(`
    package main

    import (
    	"log"
    	"os/exec"
    )

    func main() {
    	syscall.Exec("/bin/cat", []string{ "/etc/passwd" }, nil)
    }`, analyzer)

	checkTestResults(t, issues, 1, "Subprocess launching should be audited.")
}
