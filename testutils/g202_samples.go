package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG202 - SQL query string building via string concatenation
var SampleCodeG202 = []CodeSample{
	{[]string{`
// infixed concatenation
package main

import (
	"database/sql"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}

  q := "INSERT INTO foo (name) VALUES ('" + os.Args[0] + "')"
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
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
`}, 1, gosec.NewConfig()},
	{[]string{`
// case insensitive match
package main

import (
	"database/sql"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("select * from foo where name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// context match
package main

import (
    "context"
	"database/sql"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.QueryContext(context.Background(), "select * from foo where name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// DB transaction check
package main

import (
    "context"
	"database/sql"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(context.Background(), "select * from foo where name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	if err := tx.Commit(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// multiple string concatenation
package main

import (
	"database/sql"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM foo" + "WHERE name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// false positive
package main

import (
	"database/sql"
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
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
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
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

const gender = "M"
`, `
package main

import (
		"database/sql"
)

const age = "32"

var staticQuery = "SELECT * FROM foo WHERE age < "

func main(){
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
				panic(err)
		}
		rows, err := db.Query("SELECT * FROM foo WHERE gender = " + gender)
		if err != nil {
				panic(err)
		}
		defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// ExecContext match
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	result, err := db.ExecContext(context.Background(), "select * from foo where name = "+os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}`}, 1, gosec.NewConfig()},
	{[]string{`
// Exec match
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	result, err := db.Exec("select * from foo where name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
	"fmt"
)
const gender = "M"
const age = "32"

var staticQuery = "SELECT * FROM foo WHERE age < "

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	result, err := db.Exec("SELECT * FROM foo WHERE gender = " + gender)
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}
`}, 0, gosec.NewConfig()},
}
