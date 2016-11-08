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
	gas "github.com/GoASTScanner/gas/core"
	"testing"
)

const initOnlyImportSrc = `
package main
import (
	_ "crypto/md5"
	"fmt"
)
func main() {
	for _, arg := range os.Args {
		fmt.Println(arg)
	}
}`

func TestInitOnlyImport(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewBlacklist_crypto_md5(config))
	issues := gasTestRunner(initOnlyImportSrc, analyzer)
	checkTestResults(t, issues, 0, "")
}
