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
	gas "github.com/HewlettPackard/gas/core"
	"testing"
)

func TestTempfiles(t *testing.T) {
	analyzer := gas.NewAnalyzer(false, nil)
	analyzer.AddRule(NewBadTempFile())

	source := `
        package samples

        import (
        	"io/ioutil"
        	"os"
        )

        func main() {

        	file1, _ := os.Create("/tmp/demo1")
        	defer file1.Close()

        	ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
        }
        `

	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 2, "shared tmp directory")
}
