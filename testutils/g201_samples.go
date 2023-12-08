package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG201 - SQL injection via format string
var SampleCodeG201 = []CodeSample{
	{[]string{`
// Format string without proper quoting
package main

import (
	"database/sql"
	"fmt"
	"os"
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
`}, 1, gosec.NewConfig()},
	{[]string{`
// Format string without proper quoting case insensitive
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("select * from foo where name = '%s'", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// Format string without proper quoting with context
package main
import (
	"context"
	"database/sql"
	"fmt"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("select * from foo where name = '%s'", os.Args[1])
	rows, err := db.QueryContext(context.Background(), q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// Format string without proper quoting with transaction
package main
import (
	"context"
	"database/sql"
	"fmt"
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
	q := fmt.Sprintf("select * from foo where name = '%s'", os.Args[1])
	rows, err := tx.QueryContext(context.Background(), q)
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
// Format string false positive, safe string spec.
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM foo where id = %d", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Format string false positive
package main

import (
		"database/sql"
)

const staticQuery = "SELECT * FROM foo WHERE age < 32"

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
`}, 0, gosec.NewConfig()},
	{[]string{`
// Format string false positive, quoted formatter argument.
package main

import (
	"database/sql"
	"fmt"
	"os"
	"github.com/lib/pq"
)

func main(){
	db, err := sql.Open("postgres", "localhost")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM %s where id = 1", pq.QuoteIdentifier(os.Args[1]))
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// false positive
package main

import (
	"database/sql"
	"fmt"
)

const Table = "foo"
func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM %s where id = 1", Table)
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
import (
	"fmt"
)

func main(){
	fmt.Sprintln()
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Format string with \n\r
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM foo where\n name = '%s'", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// Format string with \n\r
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM foo where\nname = '%s'", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// SQLI by db.Query(some).Scan(&other)
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main() {
	var name string
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT name FROM users where id = '%s'", os.Args[1])
	row := db.QueryRow(q)
	err = row.Scan(&name)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}`}, 1, gosec.NewConfig()},
	{[]string{`
// SQLI by db.Query(some).Scan(&other)
package main

import (
	"database/sql"
	"fmt"
	"os"
)

func main() {
	var name string
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT name FROM users where id = '%s'", os.Args[1])
	err = db.QueryRow(q).Scan(&name)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}`}, 1, gosec.NewConfig()},
	{[]string{`
// SQLI by db.Prepare(some)
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

const Table = "foo"

func main() {
	var album string
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT name FROM users where '%s' = ?", os.Args[1])
	stmt, err := db.Prepare(q)
	if err != nil {
		log.Fatal(err)
	}
	stmt.QueryRow(fmt.Sprintf("%s", os.Args[2])).Scan(&album)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatal(err)
		}
	}
	defer stmt.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// SQLI by db.PrepareContext(some)
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
)

const Table = "foo"

func main() {
	var album string
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT name FROM users where '%s' = ?", os.Args[1])
	stmt, err := db.PrepareContext(context.Background(), q)
	if err != nil {
		log.Fatal(err)
	}
	stmt.QueryRow(fmt.Sprintf("%s", os.Args[2])).Scan(&album)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatal(err)
		}
	}
	defer stmt.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// false positive
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

const Table = "foo"

func main() {
	var album string
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("SELECT * FROM album WHERE id = ?")
	if err != nil {
		log.Fatal(err)
	}
	stmt.QueryRow(fmt.Sprintf("%s", os.Args[1])).Scan(&album)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatal(err)
		}
	}
	defer stmt.Close()
}
`}, 0, gosec.NewConfig()},
}
