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

func TestSQLInjectionViaConcatenation(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrConcat("TEST", config))

	source := `
        package main
        import (
                "database/sql"
                //_ "github.com/mattn/go-sqlite3"
                "os"
        )
        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                rows, err := db.Query("SELECT * FROM foo WHERE name = " + os.Args[1])
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }
        `
	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "SQL string concatenation")
}

func TestSQLInjectionViaIntepolation(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrFormat("TEST", config))

	source := `
        package main
        import (
                "database/sql"
                "fmt"
                "os"
                //_ "github.com/mattn/go-sqlite3"
        )
        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                q := fmt.Sprintf("SELECT * FROM foo where name = '%s'", os.Args[1])
                rows, err := db.Query(q)
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }
        `
	issues := gasTestRunner(source, analyzer)
	checkTestResults(t, issues, 1, "SQL string formatting")
}

func TestSQLInjectionFalsePositiveA(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrConcat("TEST1", config))
	analyzer.AddRule(NewSqlStrFormat("TEST2", config))

	source := `

        package main
        import (
                "database/sql"
                //_ "github.com/mattn/go-sqlite3"
        )

        var staticQuery = "SELECT * FROM foo WHERE age < 32"

        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                rows, err := db.Query(staticQuery)
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }

        `
	issues := gasTestRunner(source, analyzer)

	checkTestResults(t, issues, 0, "Not expected to match")
}

func TestSQLInjectionFalsePositiveB(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrConcat("TEST1", config))
	analyzer.AddRule(NewSqlStrFormat("TEST2", config))

	source := `

        package main
        import (
                "database/sql"
                //_ "github.com/mattn/go-sqlite3"
        )

        var staticQuery = "SELECT * FROM foo WHERE age < 32"

        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                rows, err := db.Query(staticQuery)
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }

        `
	issues := gasTestRunner(source, analyzer)

	checkTestResults(t, issues, 0, "Not expected to match")
}

func TestSQLInjectionFalsePositiveC(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrConcat("TEST1", config))
	analyzer.AddRule(NewSqlStrFormat("TEST2", config))

	source := `

        package main
        import (
                "database/sql"
                //_ "github.com/mattn/go-sqlite3"
        )

        var staticQuery = "SELECT * FROM foo WHERE age < "

        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                rows, err := db.Query(staticQuery + "32")
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }

        `
	issues := gasTestRunner(source, analyzer)

	checkTestResults(t, issues, 0, "Not expected to match")
}

func TestSQLInjectionFalsePositiveD(t *testing.T) {
	config := map[string]interface{}{"ignoreNosec": false}
	analyzer := gas.NewAnalyzer(config, nil)
	analyzer.AddRule(NewSqlStrConcat("TEST1", config))
	analyzer.AddRule(NewSqlStrFormat("TEST2", config))

	source := `

        package main
        import (
                "database/sql"
                //_ "github.com/mattn/go-sqlite3"
        )

				const age = "32"
        var staticQuery = "SELECT * FROM foo WHERE age < "

        func main(){
                db, err := sql.Open("sqlite3", ":memory:")
                if err != nil {
                        panic(err)
                }
                rows, err := db.Query(staticQuery + age)
                if err != nil {
                        panic(err)
                }
                defer rows.Close()
        }

        `
	issues := gasTestRunner(source, analyzer)

	checkTestResults(t, issues, 0, "Not expected to match")
}
