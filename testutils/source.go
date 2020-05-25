package testutils

import "github.com/securego/gosec/v2"

// CodeSample encapsulates a snippet of source code that compiles, and how many errors should be detected
type CodeSample struct {
	Code   []string
	Errors int
	Config gosec.Config
}

var (
	// SampleCodeG101 code snippets for hardcoded credentials
	SampleCodeG101 = []CodeSample{{[]string{`
package main
import "fmt"
func main() {
	username := "admin"
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Entropy check should not report this error by default
package main
import "fmt"
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Doing something with: ", username, password)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main
import "fmt"
var password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`}, 1, gosec.NewConfig()}, {[]string{`
package main
import "fmt"
const password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`}, 1, gosec.NewConfig()}, {[]string{`
package main
import "fmt"
const (
	username = "user"
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	fmt.Println("Doing something with: ", username, password)
}`}, 1, gosec.NewConfig()}, {[]string{`
package main
var password string
func init() {
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
}`}, 1, gosec.NewConfig()}, {[]string{`
package main
const (
	ATNStateSomethingElse = 1
	ATNStateTokenStart = 42
)
func main() {
	println(ATNStateTokenStart)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main
const (
	ATNStateTokenStart = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	println(ATNStateTokenStart)
}`}, 1, gosec.NewConfig()},
		{[]string{`
package main
import "fmt"
func main() {
	var password string
	if password == "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" {
		fmt.Println("password equality") 
	}
}`}, 1, gosec.NewConfig()},
		{[]string{`
package main
import "fmt"
func main() {
	var password string
	if password != "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" {
		fmt.Println("password equality") 
	}
}`}, 1, gosec.NewConfig()},
		{[]string{`
package main
import "fmt"
func main() {
	var p string
	if p != "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" {
		fmt.Println("password equality") 
	}
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG102 code snippets for network binding
	SampleCodeG102 = []CodeSample{
		// Bind to all networks explicitly
		{[]string{`
package main
import (
	"log"
   	"net"
)
func main() {
	l, err := net.Listen("tcp", "0.0.0.0:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`}, 1, gosec.NewConfig()},

		// Bind to all networks implicitly (default if host omitted)
		{[]string{`
package main
import (
	"log"
   	"net"
)
func main() {
   	l, err := net.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`}, 1, gosec.NewConfig()},
		// Bind to all networks indirectly through a parsing function
		{[]string{`
package main
import (
	"log"
   	"net"
)
func parseListenAddr(listenAddr string) (network string, addr string) {
	return "", ""
}
func main() {
	addr := ":2000"
	l, err := net.Listen(parseListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`}, 1, gosec.NewConfig()},
		// Bind to all networks indirectly through a parsing function
		{[]string{`
package main
import (
	"log"
   	"net"
)
const addr = ":2000"
func parseListenAddr(listenAddr string) (network string, addr string) {
	return "", ""
}
func main() {
	l, err := net.Listen(parseListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`}, 1, gosec.NewConfig()},
		{[]string{`
package main
import (
	"log"
   	"net"
)
const addr = "0.0.0.0:2000"

func main() {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`}, 1, gosec.NewConfig()},
	}
	// SampleCodeG103 find instances of unsafe blocks for auditing purposes
	SampleCodeG103 = []CodeSample{
		{[]string{`
package main
import (
	"fmt"
	"unsafe"
)
type Fake struct{}
func (Fake) Good() {}
func main() {
	unsafeM := Fake{}
   	unsafeM.Good()
   	intArray := [...]int{1, 2}
   	fmt.Printf("\nintArray: %v\n", intArray)
   	intPtr := &intArray[0]
   	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n", intPtr, *intPtr)
   	addressHolder := uintptr(unsafe.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
   	intPtr = (*int)(unsafe.Pointer(addressHolder))
   	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n\n", intPtr, *intPtr)
}`}, 3, gosec.NewConfig()}}

	// SampleCodeG104 finds errors that aren't being handled
	SampleCodeG104 = []CodeSample{
		{[]string{`
package main
import "fmt"
func test() (int,error) {
	return 0, nil
}
func main() {
	v, _ := test()
	fmt.Println(v)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main
import (
	"io/ioutil"
	"os"
	"fmt"
)
func a() error {
	return fmt.Errorf("This is an error")
}
func b() {
	fmt.Println("b")
	ioutil.WriteFile("foo.txt", []byte("bar"), os.ModeExclusive)
}
func c() string {
	return fmt.Sprintf("This isn't anything")
}
func main() {
	_ = a()
	a()
	b()
	c()
}`}, 2, gosec.NewConfig()}, {[]string{`
package main
import "fmt"
func test() error {
	return nil
}
func main() {
	e := test()
	fmt.Println(e)
}`}, 0, gosec.NewConfig()}, {[]string{`
// +build go1.10

package main
import "strings"
func main() {
	var buf strings.Builder
	_, err := buf.WriteString("test string")
	if err != nil {
		panic(err)
	}
}`, `
package main
func dummy(){}
`}, 0, gosec.NewConfig()}, {[]string{`
package main

import (
	"bytes"
)

type a struct {
	buf *bytes.Buffer
}

func main() {
	a := &a{
		buf: new(bytes.Buffer),
	}
	a.buf.Write([]byte{0})
}
`}, 0, gosec.NewConfig()}, {[]string{`
package main
import (
	"io/ioutil"
	"os"
	"fmt"
)
func a() {
	fmt.Println("a")
	ioutil.WriteFile("foo.txt", []byte("bar"), os.ModeExclusive)
}
func main() {
	a()
}`}, 0, gosec.Config{"G104": map[string]interface{}{"ioutil": []interface{}{"WriteFile"}}}}, {[]string{`
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

func createBuffer() *bytes.Buffer {
	return new(bytes.Buffer)
}

func main() {
	new(bytes.Buffer).WriteString("*bytes.Buffer")
	fmt.Fprintln(os.Stderr, "fmt")
	new(strings.Builder).WriteString("*strings.Builder")
	_, pw := io.Pipe()
	pw.CloseWithError(io.EOF)

	createBuffer().WriteString("*bytes.Buffer")
	b := createBuffer()
	b.WriteString("*bytes.Buffer")
}`}, 0, gosec.NewConfig()}}  // it shoudn't return any errors because all method calls are whitelisted by default

	// SampleCodeG104Audit finds errors that aren't being handled in audit mode
	SampleCodeG104Audit = []CodeSample{
		{[]string{`
package main
import "fmt"
func test() (int,error) {
	return 0, nil
}
func main() {
	v, _ := test()
	fmt.Println(v)
}`}, 1, gosec.Config{gosec.Globals: map[gosec.GlobalOption]string{gosec.Audit: "enabled"}}}, {[]string{`
package main
import (
	"io/ioutil"
	"os"
	"fmt"
)
func a() error {
	return fmt.Errorf("This is an error")
}
func b() {
	fmt.Println("b")
	ioutil.WriteFile("foo.txt", []byte("bar"), os.ModeExclusive)
}
func c() string {
	return fmt.Sprintf("This isn't anything")
}
func main() {
	_ = a()
	a()
	b()
	c()
}`}, 3, gosec.Config{gosec.Globals: map[gosec.GlobalOption]string{gosec.Audit: "enabled"}}}, {[]string{`
package main
import "fmt"
func test() error {
	return nil
}
func main() {
	e := test()
	fmt.Println(e)
}`}, 0, gosec.Config{gosec.Globals: map[gosec.GlobalOption]string{gosec.Audit: "enabled"}}}, {[]string{`
// +build go1.10

package main
import "strings"
func main() {
	var buf strings.Builder
	_, err := buf.WriteString("test string")
	if err != nil {
		panic(err)
	}
}`, `
package main
func dummy(){}
`}, 0, gosec.Config{gosec.Globals: map[gosec.GlobalOption]string{gosec.Audit: "enabled"}}}}

	// SampleCodeG106 - ssh InsecureIgnoreHostKey
	SampleCodeG106 = []CodeSample{{[]string{`
package main
import (
        "golang.org/x/crypto/ssh"
)
func main() {
        _ =  ssh.InsecureIgnoreHostKey()
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG107 - SSRF via http requests with variable url
	SampleCodeG107 = []CodeSample{{[]string{`
// Input from the std in is considered insecure
package main
import (
	"net/http"
	"io/ioutil"
	"fmt"
	"os"
	"bufio"
)
func main() {
	in := bufio.NewReader(os.Stdin)
	url, err := in.ReadString('\n')
	if err != nil {
		panic(err)
	}
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
  	defer resp.Body.Close()
  	body, err := ioutil.ReadAll(resp.Body)
  	if err != nil {
    		panic(err)
  	}
  	fmt.Printf("%s", body)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Variable defined a package level can be changed at any time
// regardless of the initial value
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

var url string = "https://www.google.com"

func main() {
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", body)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Environmental variables are not considered as secure source
package main
import (
	"net/http"
	"io/ioutil"
	"fmt"
	"os"
)
func main() {
	url := os.Getenv("tainted_url")
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
			panic(err)
	}
	fmt.Printf("%s", body)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Constant variables or hard-coded strings are secure
package main

import (
	"fmt"
	"net/http"
)
const url = "http://127.0.0.1"
func main() {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}`}, 0, gosec.NewConfig()}, {[]string{`
// A variable at function scope which is initialized to
// a constant string is secure (e.g. cannot be changed concurrently)
package main

import (
	"fmt"
	"net/http"
)
func main() {
    var url string = "http://127.0.0.1"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}`}, 0, gosec.NewConfig()}, {[]string{`
// A variable at function scope which is initialized to
// a constant string is secure (e.g. cannot be changed concurrently)
package main

import (
	"fmt"
	"net/http"
)
func main() {
	url := "http://127.0.0.1"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}`}, 0, gosec.NewConfig()}, {[]string{`
// A variable at function scope which is initialized to
// a constant string is secure (e.g. cannot be changed concurrently)
package main

import (
	"fmt"
	"net/http"
)
func main() {
	url1 := "test"
    var url2 string = "http://127.0.0.1"
	url2 = url1
	resp, err := http.Get(url2)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}`}, 0, gosec.NewConfig()}, {[]string{`
// An exported variable declared a packaged scope is not secure 
// because it can changed at any time
package main

import (
	"fmt"
	"net/http"
)

var Url string

func main() {
	resp, err := http.Get(Url)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}`}, 1, gosec.NewConfig()}, {[]string{`
// An url provided as a function argument is not secure
package main

import (
	"fmt"
	"net/http"
)
func get(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
    }
    fmt.Println(resp.Status)
}
func main() {
	url := "http://127.0.0.1"
	get(url)
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG108 - pprof endpoint automatically exposed
	SampleCodeG108 = []CodeSample{{[]string{`
package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World!")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World!")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG109 - Potential Integer OverFlow
	SampleCodeG109 = []CodeSample{
		{[]string{`
package main

import (
	"fmt"
	"strconv"
)

func main() {
	bigValue, err := strconv.Atoi("2147483648")
	if err != nil {
		panic(err)
	}
	value := int32(bigValue)
	fmt.Println(value)
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"strconv"
)

func main() {
	bigValue, err := strconv.Atoi("32768")
	if err != nil {
		panic(err)
	}
	if int16(bigValue) < 0 {
		fmt.Println(bigValue)
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"strconv"
)

func main() {
	bigValue, err := strconv.Atoi("2147483648")
	if err != nil {
		panic(err)
	}
	fmt.Println(bigValue)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"strconv"
)

func main() {
	bigValue, err := strconv.Atoi("2147483648")
	if err != nil {
		panic(err)
	}
	fmt.Println(bigValue)
	test()
}

func test() {
	bigValue := 30
	value := int32(bigValue)
	fmt.Println(value)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"strconv"
)

func main() {
	value := 10
	if value == 10 {
		value, _ := strconv.Atoi("2147483648")
		fmt.Println(value)
	}
	v := int32(value)
	fmt.Println(v)
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG110 - potential DoS vulnerability via decompression bomb
	SampleCodeG110 = []CodeSample{
		{[]string{`
package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"os"
)

func main() {
	buff := []byte{120, 156, 202, 72, 205, 201, 201, 215, 81, 40, 207,
		47, 202, 73, 225, 2, 4, 0, 0, 255, 255, 33, 231, 4, 147}
	b := bytes.NewReader(buff)

	r, err := zlib.NewReader(b)
	if err != nil {
		panic(err)
	}
	io.Copy(os.Stdout, r)

	r.Close()
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"archive/zip"
	"io"
	"os"
	"strconv"
)

func main() {
	r, err := zip.OpenReader("tmp.zip")
	if err != nil {
		panic(err)
	}
	defer r.Close()

	for i, f := range r.File {
		out, err := os.OpenFile("output" + strconv.Itoa(i), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			panic(err)
		}

		rc, err := f.Open()
		if err != nil {
			panic(err)
		}

		_, err = io.Copy(out, rc)

		out.Close()
		rc.Close()

		if err != nil {
			panic(err)
		}
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"io"
	"os"
)

func main() {
	s, err := os.Open("src")
	if err != nil {
		panic(err)
	}
	defer s.Close()

	d, err := os.Create("dst")
	if err != nil {
		panic(err)
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	if  err != nil {
		panic(err)
	}
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG201 - SQL injection via format string
	SampleCodeG201 = []CodeSample{
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 1, gosec.NewConfig()}, {[]string{`
// Format string without proper quoting with transation
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 0, gosec.NewConfig()}, {[]string{`
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
}`}, 0, gosec.NewConfig()}, {[]string{`
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
}`}, 0, gosec.NewConfig()}, {[]string{`
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
}`}, 0, gosec.NewConfig()}, {[]string{`
package main
import (
	"fmt"
)

func main(){
	fmt.Sprintln()
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG202 - SQL query string building via string concatenation
	SampleCodeG202 = []CodeSample{
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 1, gosec.NewConfig()}, {[]string{`
// DB transation check
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 1, gosec.NewConfig()}, {[]string{`
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
}`}, 0, gosec.NewConfig()}, {[]string{`
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
`}, 0, gosec.NewConfig()}, {[]string{`
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
`}, 0, gosec.NewConfig()}}

	// SampleCodeG203 - Template checks
	SampleCodeG203 = []CodeSample{
		{[]string{`
// We assume that hardcoded template strings are safe as the programmer would
// need to be explicitly shooting themselves in the foot (as below)
package main
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
}`}, 0, gosec.NewConfig()}, {[]string{
			`
// Using a variable to initialize could potentially be dangerous. Under the
// current model this will likely produce some false positives.
package main
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
}`}, 1, gosec.NewConfig()}, {[]string{
			`
package main
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
}`}, 1, gosec.NewConfig()}, {[]string{
			`
package main
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
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG204 - Subprocess auditing
	SampleCodeG204 = []CodeSample{{[]string{`
package main
import (
	"log"
	"os/exec"
	"context"
)
func main() {
	err := exec.CommandContext(context.Background(), "git", "rev-parse", "--show-toplavel").Run()
 	if err != nil {
		log.Fatal(err)
	}
  	log.Printf("Command finished with error: %v", err)
}`}, 0, gosec.NewConfig()}, {[]string{`
// Calling any function which starts a new process with using
// command line arguments as it's arguments is considered dangerous
package main
import (
	"log"
	"os"
	"os/exec"
)
func main() {
	err := exec.CommandContext(context.Background(), os.Args[0], "5").Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Command finished with error: %v", err)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Initializing a local variable using a environmental
// variable is consider as a dangerous user input
package main
import (
	"log"
	"os"
	"os/exec"
)
func main() {
	run := "sleep" + os.Getenv("SOMETHING")
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}`}, 1, gosec.NewConfig()}, {[]string{`
// gosec doesn't have enough context to decide that the
// command argument of the RunCmd function is harcoded string
// and that's why it's better to warn the user so he can audit it
package main

import (
	"log"
	"os/exec"
)

func RunCmd(command string) {
	cmd := exec.Command(command, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
}

func main() {
	RunCmd("sleep")
}`}, 1, gosec.NewConfig()}, {[]string{`
// syscall.Exec function called with harcoded arguments
// shouldn't be consider as a command injection
package main
import (
	"fmt"
	"syscall"
)
func main() {
	err := syscall.Exec("/bin/cat", []string{"/etc/passwd"}, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}`}, 0, gosec.NewConfig()},
		{[]string{`
package main

import (
	"fmt"
	"syscall"
)

func RunCmd(command string) {
	_, err := syscall.ForkExec(command, []string{}, nil)
	if err != nil {
	    fmt.Printf("Error: %v\n", err)
	}
}

func main() {
	RunCmd("sleep")
}`}, 1, gosec.NewConfig(),
		},
		{[]string{`
package main

import (
	"fmt"
	"syscall"
)

func RunCmd(command string) {
	_, err := syscall.StartProcess(command, []string{}, nil)
	if err != nil {
	    fmt.Printf("Error: %v\n", err)
	}
}

func main() {
	RunCmd("sleep")
}`}, 1, gosec.NewConfig(),
		},
		{[]string{`
// starting a process with a variable as an argument
// even if not constant is not considered as dangerous
// because it has harcoded value
package main
import (
	"log"
	"os/exec"
)
func main() {
	run := "sleep"
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG301 - mkdir permission check
	SampleCodeG301 = []CodeSample{{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Mkdir("/tmp/mydir", 0777)
	if err != nil {
		fmt.Println("Error when creating a directory!")
		return
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.MkdirAll("/tmp/mydir", 0777)
	if err != nil {
		fmt.Println("Error when creating a directory!")
		return
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Mkdir("/tmp/mydir", 0600)
	if err != nil {
		fmt.Println("Error when creating a directory!")
		return
	}
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG302 - file create / chmod permissions check
	SampleCodeG302 = []CodeSample{{[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Chmod("/tmp/somefile", 0777)
	if err != nil {
		fmt.Println("Error when changing file permissions!")
		return
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	_, err := os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening a file!")
		return
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.Chmod("/tmp/mydir", 0400)
	if err != nil {
		fmt.Println("Error")
		return
	}
}`}, 0, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"os"
)

func main() {
	_, err := os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error opening a file!")
		return
	}
}
`}, 0, gosec.NewConfig()}}

	// SampleCodeG303 - bad tempfile permissions & hardcoded shared path
	SampleCodeG303 = []CodeSample{{[]string{`
package samples

import (
	"fmt"
	"io/ioutil"
)

func main() {
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG304 - potential file inclusion vulnerability
	SampleCodeG304 = []CodeSample{{[]string{`
package main
import (
"os"
"io/ioutil"
"log"
)
func main() {
	f := os.Getenv("tainted_file")
	body, err := ioutil.ReadFile(f)
	if err != nil {
	log.Printf("Error: %v\n", err)
	}
	log.Print(body)

}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
  		title := r.URL.Query().Get("title")
		f, err := os.Open(title)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		body := make([]byte, 5)
		if _, err = f.Read(body); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		fmt.Fprintf(w, "%s", body)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"log"
	"os"
	"io/ioutil"
)

	func main() {
		f2 := os.Getenv("tainted_file2")
		body, err := ioutil.ReadFile("/tmp/" + f2)
		if err != nil {
		log.Printf("Error: %v\n", err)
	  }
		log.Print(body)
 }`}, 1, gosec.NewConfig()}, {[]string{`
 package main

 import (
	 "bufio"
	 "fmt"
	 "os"
	 "path/filepath"
 )

func main() {
	reader := bufio.NewReader(os.Stdin)
  fmt.Print("Please enter file to read: ")
	file, _ := reader.ReadString('\n')
	file = file[:len(file)-1]
	f, err := os.Open(filepath.Join("/tmp/service/", file))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	contents := make([]byte, 15)
  if _, err = f.Read(contents); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
  fmt.Println(string(contents))
}`}, 1, gosec.NewConfig()}, {[]string{`
package main

import (
	"log"
	"os"
	"io/ioutil"
	"path/filepath"
)

func main() {
	dir := os.Getenv("server_root")
	f3 := os.Getenv("tainted_file3")
	// edge case where both a binary expression and file Join are used.
	body, err := ioutil.ReadFile(filepath.Join("/var/"+dir, f3))
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
	log.Print(body)
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG305 - File path traversal when extracting zip archives
	SampleCodeG305 = []CodeSample{{[]string{`
package unzip

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func unzip(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode()) // #nosec
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}`}, 1, gosec.NewConfig()}, {[]string{`
package unzip

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func unzip(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
                archiveFile := file.Name
		path := filepath.Join(target, archiveFile)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode()) // #nosec
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG306 - Poor permissions for WriteFile
	SampleCodeG306 = []CodeSample{
		{[]string{`package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	
	d1 := []byte("hello\ngo\n")
	err := ioutil.WriteFile("/tmp/dat1", d1, 0744)
	check(err)

	allowed := ioutil.WriteFile("/tmp/dat1", d1, 0600)
	check(allowed)
	
	f, err := os.Create("/tmp/dat2")
	check(err)
	
	defer f.Close()
	
	d2 := []byte{115, 111, 109, 101, 10}
	n2, err := f.Write(d2)

	defer check(err)
	fmt.Printf("wrote %d bytes\n", n2)
	
	n3, err := f.WriteString("writes\n")
	fmt.Printf("wrote %d bytes\n", n3)
	
	f.Sync()
	
	w := bufio.NewWriter(f)
	n4, err := w.WriteString("buffered\n")
	fmt.Printf("wrote %d bytes\n", n4)
	
	w.Flush()

}`}, 1, gosec.NewConfig()}}
	// SampleCodeG307 - Unsafe defer of os.Close
	SampleCodeG307 = []CodeSample{
		{[]string{`package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	d1 := []byte("hello\ngo\n")
	err := ioutil.WriteFile("/tmp/dat1", d1, 0744)
	check(err)

	allowed := ioutil.WriteFile("/tmp/dat1", d1, 0600)
	check(allowed)

	f, err := os.Create("/tmp/dat2")
	check(err)

	defer f.Close()

	d2 := []byte{115, 111, 109, 101, 10}
	n2, err := f.Write(d2)

	defer check(err)
	fmt.Printf("wrote %d bytes\n", n2)
	
	n3, err := f.WriteString("writes\n")
	fmt.Printf("wrote %d bytes\n", n3)
	
	f.Sync()
	
	w := bufio.NewWriter(f)
	n4, err := w.WriteString("buffered\n")
	fmt.Printf("wrote %d bytes\n", n4)
	
	w.Flush()

}`}, 1, gosec.NewConfig()}}

	// SampleCodeG401 - Use of weak crypto MD5
	SampleCodeG401 = []CodeSample{
		{[]string{`
package main
import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	defer func() {
	  err := f.Close()
	  if err != nil {
		 log.Printf("error closing the file: %s", err)
	  }
	}()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG401b - Use of weak crypto SHA1
	SampleCodeG401b = []CodeSample{
		{[]string{`
package main
import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"os"
)
func main() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG402 - TLS settings
	SampleCodeG402 = []CodeSample{{[]string{`
// InsecureSkipVerify
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`}, 1, gosec.NewConfig()}, {[]string{
		`
// Insecure minimum version
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: 0},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`}, 1, gosec.NewConfig()}, {[]string{`
// Insecure max version
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MaxVersion: 0},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}
`}, 1, gosec.NewConfig()}, {
		[]string{`
// Insecure ciphersuite selection
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{CipherSuites: []uint16{
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						},},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG403 - weak key strength
	SampleCodeG403 = []CodeSample{
		{[]string{`
package main
import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)
func main() {
	//Generate Private Key
	pvk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG404 - weak random number
	SampleCodeG404 = []CodeSample{
		{[]string{`
package main
import "crypto/rand"
func main() {
	good, _ := rand.Read(nil)
	println(good)
}`}, 0, gosec.NewConfig()}, {[]string{`
package main
import "math/rand"
func main() {
	bad := rand.Int()
	println(bad)
}`}, 1, gosec.NewConfig()}, {[]string{`
package main
import (
	"crypto/rand"
	mrand "math/rand"
)
func main() {
	good, _ := rand.Read(nil)
	println(good)
	i := mrand.Int31()
	println(i)
}`}, 0, gosec.NewConfig()}}

	// SampleCodeG501 - Blacklisted import MD5
	SampleCodeG501 = []CodeSample{
		{[]string{`
package main
import (
	"crypto/md5"
	"fmt"
	"os"
)
func main() {
	for _, arg := range os.Args {
		fmt.Printf("%x - %s\n", md5.Sum([]byte(arg)), arg)
	}
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG502 - Blacklisted import DES
	SampleCodeG502 = []CodeSample{
		{[]string{`
package main
import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)
func main() {
	block, err := des.NewCipher([]byte("sekritz"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG503 - Blacklisted import RC4
	SampleCodeG503 = []CodeSample{{[]string{`
package main
import (
	"crypto/rc4"
	"encoding/hex"
	"fmt"
)
func main() {
	cipher, err := rc4.NewCipher([]byte("sekritz"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG504 - Blacklisted import CGI
	SampleCodeG504 = []CodeSample{{[]string{`
package main
import (
	"net/http/cgi"
	"net/http"
 )
func main() {
	cgi.Serve(http.FileServer(http.Dir("/usr/share/doc")))
}`}, 1, gosec.NewConfig()}}
	// SampleCodeG505 - Blacklisted import SHA1
	SampleCodeG505 = []CodeSample{
		{[]string{`
package main
import (
	"crypto/sha1"
	"fmt"
	"os"
)
func main() {
	for _, arg := range os.Args {
		fmt.Printf("%x - %s\n", sha1.Sum([]byte(arg)), arg)
	}
}`}, 1, gosec.NewConfig()}}

	// SampleCodeG601 - Implicit aliasing over range statement
	SampleCodeG601 = []CodeSample{
		{[]string{`
package main

import "fmt"

var vector []*string
func appendVector(s *string) {
	vector = append(vector, s)
}

func printVector() {
	for _, item := range vector {
		fmt.Printf("%s", *item)
	}
	fmt.Println()
}

func foo() (int, *string, string) {
	for _, item := range vector {
		return 0, &item, item
	}
}

func main() {
	for _, item := range []string{"A", "B", "C"} {
		appendVector(&item)
	}

	printVector()

	zero, c_star, c := foo()
	fmt.Printf("%d %v %s", zero, c_start, c)
}`,
		}, 1, gosec.NewConfig()},
		{[]string{`
// see: github.com/securego/gosec/issues/475
package main
import (
    "fmt"
)
func main() {
    sampleMap := map[string]string{}
    sampleString := "A string"
    for sampleString, _ = range sampleMap {
        fmt.Println(sampleString)
    }
}`}, 0, gosec.NewConfig()},
	}

	// SampleCodeBuildTag - G601 build tags
	SampleCodeBuildTag = []CodeSample{{[]string{`
// +build tag
package main
func main() {
  fmt.Println("no package imported error")
}`}, 1, gosec.NewConfig()}}

	// SampleCodeCgo - Cgo file sample
	SampleCodeCgo = []CodeSample{{[]string{`
package main

import (
        "fmt"
        "unsafe"
)

/*
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int printData(unsigned char *data) {
    return printf("cData: %lu \"%s\"\n", (long unsigned int)strlen(data), data);
}
*/
import "C"

func main() {
        // Allocate C data buffer.
        width, height := 8, 2
        lenData := width * height
        // add string terminating null byte
        cData := (*C.uchar)(C.calloc(C.size_t(lenData+1), C.sizeof_uchar))

        // When no longer in use, free C allocations.
        defer C.free(unsafe.Pointer(cData))

        // Go slice reference to C data buffer,
        // minus string terminating null byte
        gData := (*[1 << 30]byte)(unsafe.Pointer(cData))[:lenData:lenData]

        // Write and read cData via gData.
        for i := range gData {
                gData[i] = '.'
        }
        copy(gData[0:], "Data")
        gData[len(gData)-1] = 'X'
        fmt.Printf("gData: %d %q\n", len(gData), gData)
        C.printData(cData)
}
`}, 0, gosec.NewConfig()}}
)
