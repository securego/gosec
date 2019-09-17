package testutils

import "github.com/securego/gosec"

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
}`}, 1, gosec.NewConfig()}}

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
}`}, 0, gosec.Config{"G104": map[string]interface{}{"io/ioutil": []interface{}{"WriteFile"}}}}}

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
// A variable value can easily be changed no matter
// if it's a global or a local one
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
// Constant variables or harcoded strings are secure
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
// Calling any function which starts a new process
// with a function call as an argument is considered a command injection
package main
import (
	"log"
	"os/exec"
	"context"
)
func main() {
	err := exec.CommandContext(context.Background(), "sleep", "5").Run()
 	if err != nil {
		log.Fatal(err)
	}
  	log.Printf("Command finished with error: %v", err)
}`}, 1, gosec.NewConfig()}, {[]string{`
// Calling any function which starts a new process with using
// command line arguments as it's arguments is considered dangerous
package main
import (
	"log"
	"os"
	"os/exec"
)
func main() {
	err := exec.CommandContext(os.Args[0], "sleep", "5").Run()
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
import "os"
func main() {
	os.Mkdir("/tmp/mydir", 0777)
	os.Mkdir("/tmp/mydir", 0600)
	os.MkdirAll("/tmp/mydir/mysubidr", 0775)
}`}, 2, gosec.NewConfig()}}

	// SampleCodeG302 - file create / chmod permissions check
	SampleCodeG302 = []CodeSample{{[]string{`
package main
import "os"
func main() {
	os.Chmod("/tmp/somefile", 0777)
	os.Chmod("/tmp/someotherfile", 0600)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0666)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600)
}`}, 2, gosec.NewConfig()}}

	// SampleCodeG303 - bad tempfile permissions & hardcoded shared path
	SampleCodeG303 = []CodeSample{{[]string{`
package samples
import (
	"io/ioutil"
	"os"
)
func main() {
	file1, _ := os.Create("/tmp/demo1")
	defer file1.Close()
	ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
}`}, 2, gosec.NewConfig()}}

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
	// SampleCode601 - Go build tags
	SampleCode601 = []CodeSample{{[]string{`
// +build tag

package main
func main() {
  fmt.Println("no package imported error")
}`}, 1, gosec.NewConfig()}}
)
