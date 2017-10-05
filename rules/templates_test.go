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

func TestTemplateCheckSafe(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewTemplateCheck("TEST", config))

	source := `
  package samples

  import (
    "html/template"
    "os"
  )

  const tmpl = ""

  func main() {
    t := template.Must(template.New("ex").Parse(tmpl))
    v := map[string]interface{}{
      "Title":    "Test <b>World</b>",
      "Body":     template.HTML("<script>alert(1)</script>"),
    }
    t.Execute(os.Stdout, v)
  }`

	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 0, "this method will not auto-escape HTML. Verify data is well formed")
}

func TestTemplateCheckBadHTML(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewTemplateCheck("TEST", config))

	source := `
  package samples

  import (
    "html/template"
    "os"
  )

  const tmpl = ""

  func main() {
    a := "something from another place"
    t := template.Must(template.New("ex").Parse(tmpl))
    v := map[string]interface{}{
      "Title":    "Test <b>World</b>",
      "Body":     template.HTML(a),
    }
    t.Execute(os.Stdout, v)
  }`

	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "this method will not auto-escape HTML. Verify data is well formed")
}

func TestTemplateCheckBadJS(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewTemplateCheck("TEST", config))

	source := `
  package samples

  import (
    "html/template"
    "os"
  )

  const tmpl = ""

  func main() {
    a := "something from another place"
    t := template.Must(template.New("ex").Parse(tmpl))
    v := map[string]interface{}{
      "Title":    "Test <b>World</b>",
      "Body":     template.JS(a),
    }
    t.Execute(os.Stdout, v)
  }`

	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "this method will not auto-escape HTML. Verify data is well formed")
}

func TestTemplateCheckBadURL(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewTemplateCheck("TEST", config))

	source := `
  package samples

  import (
    "html/template"
    "os"
  )

  const tmpl = ""

  func main() {
    a := "something from another place"
    t := template.Must(template.New("ex").Parse(tmpl))
    v := map[string]interface{}{
      "Title":    "Test <b>World</b>",
      "Body":     template.URL(a),
    }
    t.Execute(os.Stdout, v)
  }`

	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "this method will not auto-escape HTML. Verify data is well formed")
}
