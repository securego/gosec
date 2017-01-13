// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//		 http://www.apache.org/licenses/LICENSE-2.0
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

func TestErrorsMulti(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewNoErrorCheck(config))

	issues := gasTestRunner(
		`package main

		import (
			"fmt"
		)

		func test() (int,error) {
			return 0, nil
		}

		func main() {
			v, _ := test()
			fmt.Println(v)
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

		func a() error {
			return fmt.Errorf("This is an error")
		}

		func b() {
			fmt.Println("b")
		}

		func c() string {
			return fmt.Sprintf("This isn't anything")
		}

		func main() {
			_ = a()
			a()
			b()
			_ = c()
			c()
		}`, analyzer)
	checkTestResults(t, issues, 2, "Errors unhandled")
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

func TestErrorsWhitelisted(t *testing.T) {
	config := map[string]interface{}{
		"ignoreNosec": false,
		"G104": map[string][]string{
			"compress/zlib": []string{"NewReader"},
			"io":            []string{"Copy"},
		},
	}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewNoErrorCheck(config))
	source := `package main
		import (
			"io"
			"os"
			"fmt"
			"bytes"
			"compress/zlib"
		)

		func a() error {
			return fmt.Errorf("This is an error ok")
		}

		func main() {
			// Expect at least one failure
			_ = a()

			var b bytes.Buffer
			// Default whitelist
			nbytes, _ := b.Write([]byte("Hello "))
			if nbytes <= 0 {
				os.Exit(1)
			}

			// Whitelisted via configuration
			r, _ := zlib.NewReader(&b)
			io.Copy(os.Stdout, r)
		}`
	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "Errors unhandled")
}
