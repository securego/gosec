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
// DB connection check
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
	conn, err := db.Conn(context.Background())
	if err != nil {
		panic(err)
	}
	rows, err := conn.QueryContext(context.Background(), "select * from foo where name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	if err := conn.Close(); err != nil {
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
	{[]string{`
package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "user=postgres password=password dbname=mydb sslmode=disable")
	if err!= nil {
		panic(err)
	}
	defer db.Close()

	var username string
	fmt.Println("请输入用户名:")
	fmt.Scanln(&username)

	var query string = "SELECT * FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	if err!= nil {
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

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM album WHERE id = "
	query += os.Args[0]
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	query := "SELECT * FROM album WHERE id = "
	query += os.Args[0]
	fmt.Println(query)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"database/sql"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM album WHERE id = "
	query = query + os.Args[0] // risky reassignment concatenation
	rows, err := db.Query(query)
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
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM album WHERE id = "
	query = query + "42" // safe literal reassignment concatenation
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Shadowing edge case: tainted mutation on shadowed variable - should NOT flag
// The outer 'query' is safe and passed to db.Query.
// The inner shadowed 'query' is mutated with tainted input (irrelevant).
package main

import (
	"database/sql"
	"os"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM foo WHERE id = 42" // safe outer query
	{
		query := "base"                    // shadows outer query
		query += os.Args[1]                // tainted mutation on shadow - should be ignored
		_ = query                          // prevent unused warning
	}
	rows, err := db.Query(query) // uses safe outer query
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Shadowing edge case: no mutation on shadow, safe outer - regression guard
package main

import (
	"database/sql"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM foo WHERE id = 42"
	{
		query := "shadowed but unused"
		_ = query
	}
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// package-level SQL string with tainted concatenation in init()
package main

import (
	"os"
)

var query string = "SELECT * FROM foo WHERE name = "

func init() {
	query += os.Args[1]
}
`, `
package main

import (
	"database/sql"
)

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	_, _ = db.Query(query)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// strings.Builder assembling a constant SQL fragment - should NOT flag
package main

import (
	"database/sql"
	"strings"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	ids := []int{1, 2, 3}
	var ph strings.Builder
	for i := range ids {
		if i > 0 {
			ph.WriteString(",")
		}
		ph.WriteString("?")
	}
	placeholders := ph.String()
	q := "SELECT col1 FROM table1 WHERE id IN (" + placeholders + ")"
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// strings.Builder fed with tainted input - should flag
package main

import (
	"database/sql"
	"os"
	"strings"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	var ph strings.Builder
	for _, a := range os.Args {
		ph.WriteString(a)
	}
	q := "SELECT col1 FROM table1 WHERE id IN (" + ph.String() + ")"
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// typed constant converted to string - should NOT flag
package main

import (
	"database/sql"
)

type tableName string

const usersTable tableName = "users"

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM " + string(usersTable) + " WHERE id = 1")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// typed variable converted to string - should flag
package main

import (
	"database/sql"
	"os"
)

type tableName string

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	table := tableName(os.Args[1])
	rows, err := db.Query("SELECT * FROM " + string(table) + " WHERE id = 1")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// numbered placeholder appended with an integer verb - safe
package main

import (
	"database/sql"
	"fmt"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" AND id > $%d", argCount)
	args = append(args, 10)
	argCount++
	query += fmt.Sprintf(" LIMIT $%d", argCount)
	args = append(args, 5)
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// numbered placeholder concatenated with an integer verb - safe
package main

import (
	"database/sql"
	"fmt"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	args := []any{5}
	argCount := len(args)
	query := "SELECT * FROM foo" + fmt.Sprintf(" LIMIT $%d", argCount)
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// x = x + Sprintf with an integer verb - safe
package main

import (
	"database/sql"
	"fmt"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query = query + fmt.Sprintf(" LIMIT $%d", argCount)
	args = append(args, 5)
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// string verb appended through Sprintf - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" AND name = '%s'", os.Args[1])
	_ = argCount
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// integer verb next to a string verb - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" AND id = $%d AND name = '%s'", argCount, os.Args[1])
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// %v verb appended through Sprintf - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" LIMIT %v", os.Args[1])
	_ = argCount
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// integer verb fed a string prints the string - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" LIMIT %d", os.Args[1])
	_ = argCount
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// extra string argument is printed after the format - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" LIMIT $%d", argCount, os.Args[1])
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// non-constant format string - should flag
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
	args := []any{}
	argCount := 1
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(os.Args[1], argCount)
	rows, err := db.Query(query, args...)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// format held in a named constant with an integer verb - safe
package main

import (
	"database/sql"
	"fmt"
	"os"
)

const limitClause = " LIMIT %d"

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM foo WHERE 1=1"
	n := len(os.Args)
	query += fmt.Sprintf(limitClause, n)
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// integer verb fed a reassigned string variable - should flag
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
	query := "SELECT * FROM foo WHERE 1=1"
	n := "5"
	n = os.Args[1]
	query += fmt.Sprintf(" LIMIT %d", n)
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// format variable reassigned from user input - should flag
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
	query := "SELECT * FROM foo WHERE 1=1"
	f := " LIMIT %d"
	f = os.Args[1]
	query += fmt.Sprintf(f, 5)
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// numeric type with its own Format method - should flag
package main

import (
	"database/sql"
	"fmt"
	"os"
)

type id int

func (id) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(os.Args[1]))
}

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprintf(" AND id = %d", id(len(os.Args)))
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// %c turns an integer into an arbitrary character - should flag
package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	query := "SELECT * FROM foo WHERE 1=1"
	n, _ := strconv.Atoi(os.Args[1])
	query += fmt.Sprintf(" AND name = %c", rune(n))
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// integer verbs with a variable and a constant argument - safe
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
	query := "SELECT * FROM foo WHERE 1=1"
	n := len(os.Args)
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", n, 10)
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// other fmt functions have no format to check - should flag
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
	query := "SELECT * FROM foo WHERE 1=1"
	query += fmt.Sprint(" AND name = ", os.Args[1])
	rows, err := db.Query(query)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
}
