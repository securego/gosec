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

func TestErrorsMulti(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewNoErrorCheck(config))

	issues := gasTestRunner(
		`package main

    import (
    	"fmt"
    )

    func test() (val int, err error) {
      return 0, nil
    }

    func main() {
      v, _ := test()
    }`, analyzer)

	checkTestResults(t, issues, 1, "Errors unhandled")
}

func TestErrorsSingle(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewNoErrorCheck(config))

	issues := gasTestRunner(
		`package main

    import (
    	"fmt"
    )

    func test() (err error) {
      return nil
    }

    func main() {
      _ := test()
    }`, analyzer)

	checkTestResults(t, issues, 1, "Errors unhandled")
}

func TestErrorsGood(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewNoErrorCheck(config))

	issues := gasTestRunner(
		`package main

    import (
    	"fmt"
    )

    func test() err error {
      return 0, nil
    }

    func main() {
      e := test()
    }`, analyzer)

	checkTestResults(t, issues, 0, "")
}
