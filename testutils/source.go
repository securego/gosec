package testutils

// CodeSample encapsulates a snippet of source code that compiles, and how many errors should be detected
type CodeSample struct {
	Code   string
	Errors int
}

var (
	// SampleCodeG101 code snippets for hardcoded credentials
	SampleCodeG101 = []CodeSample{{`
package main
import "fmt"
func main() {
	username := "admin"
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
// Entropy check should not report this error by default
package main
import "fmt"
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Doing something with: ", username, password)
}`, 0}, {`
package main
import "fmt"
var password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
import "fmt"
const password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
import "fmt"
const (
	username = "user"
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
var password string
func init() {
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
}`, 1}, {`
package main
const (
	ATNStateSomethingElse = 1
	ATNStateTokenStart = 42
)
func main() {
	println(ATNStateTokenStart)
}`, 0}, {`
package main
const (
	ATNStateTokenStart = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	println(ATNStateTokenStart)
}`, 1}}

	// SampleCodeG102 code snippets for network binding
	SampleCodeG102 = []CodeSample{
		// Bind to all networks explicitly
		{`
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
}`, 1},

		// Bind to all networks implicitly (default if host omitted)
		{`
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
}`, 1},
	}
	// SampleCodeG103 find instances of unsafe blocks for auditing purposes
	SampleCodeG103 = []CodeSample{
		{`
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
}`, 3}}

	// SampleCodeG104 finds errors that aren't being handled
	SampleCodeG104 = []CodeSample{
		{`
package main
import "fmt"
func test() (int,error) {
	return 0, nil
}
func main() {
	v, _ := test()
	fmt.Println(v)
}`, 1}, {`
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
}`, 3}, {`
package main
import "fmt"
func test() error {
	return nil
}
func main() {
	e := test()
	fmt.Println(e)
}`, 0}}

	// SampleCodeG105 - bignum overflow
	SampleCodeG105 = []CodeSample{{`
package main
import (
	"math/big"
)
func main() {
	z := new(big.Int)
	x := new(big.Int)
	x = x.SetUint64(2)
	y := new(big.Int)
    y = y.SetUint64(4)
   	m := new(big.Int)
    m = m.SetUint64(0)
    z = z.Exp(x, y, m)
}`, 1}}

	// SampleCodeG106 - ssh InsecureIgnoreHostKey
	SampleCodeG106 = []CodeSample{{`
package main
import (
        "golang.org/x/crypto/ssh"
)
func main() {
        _ =  ssh.InsecureIgnoreHostKey()
}`, 1}}
	// SampleCodeG201 - SQL injection via format string
	SampleCodeG201 = []CodeSample{
		{`
// Format string without proper quoting
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
}`, 1}, {`
// Format string false positive, safe string spec.
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
	q := fmt.Sprintf("SELECT * FROM foo where id = %d", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}`, 0}, {
			`
// Format string false positive
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
}`, 0}}

	// SampleCodeG202 - SQL query string building via string concatenation
	SampleCodeG202 = []CodeSample{
		{`
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
}`, 1}, {`
// false positive
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
}`, 0}, {`
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
`, 0}}

	// SampleCodeG203 - Template checks
	SampleCodeG203 = []CodeSample{
		{`
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
}`, 0}, {
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
}`, 1}, {
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
}`, 1}, {
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
}`, 1}}

	// SampleCodeG204 - Subprocess auditing
	SampleCodeG204 = []CodeSample{{`
package main
import "syscall"
func main() {
	syscall.Exec("/bin/cat", []string{ "/etc/passwd" }, nil)
}`, 1}, {`
package main
import (
	"log"
	"os/exec"
)
func main() {
	cmd := exec.Command("sleep", "5")
	err := cmd.Start()
 	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
  	err = cmd.Wait()
  	log.Printf("Command finished with error: %v", err)
}`, 1}, {`
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
}`, 1}}

	// SampleCodeG301 - mkdir permission check
	SampleCodeG301 = []CodeSample{{`
package main
import "os"
func main() {
	os.Mkdir("/tmp/mydir", 0777)
	os.Mkdir("/tmp/mydir", 0600)
	os.MkdirAll("/tmp/mydir/mysubidr", 0775)
}`, 2}}

	// SampleCodeG302 - file create / chmod permissions check
	SampleCodeG302 = []CodeSample{{`
package main
import "os"
func main() {
	os.Chmod("/tmp/somefile", 0777)
	os.Chmod("/tmp/someotherfile", 0600)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0666)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600)
}`, 2}}

	// SampleCodeG303 - bad tempfile permissions & hardcoded shared path
	SampleCodeG303 = []CodeSample{{`
package samples
import (
	"io/ioutil"
	"os"
)
func main() {
	file1, _ := os.Create("/tmp/demo1")
	defer file1.Close()
	ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
}`, 2}}

	// SampleCodeG304 - potential file inclusion vulnerability
	SampleCodeG304 = []CodeSample{{`
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

}`, 1}, {`
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
}`, 1}}

	// SampleCodeG401 - Use of weak crypto MD5
	SampleCodeG401 = []CodeSample{
		{`
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
}`, 1}}

	// SampleCodeG402 - TLS settings
	SampleCodeG402 = []CodeSample{{`
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
}`, 1}, {
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
}`, 1}, {`
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
`, 1}, {
		`
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
						tls.TLS_RSA_WITH_RC4_128_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						},},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`, 1}}

	// SampleCodeG403 - weak key strength
	SampleCodeG403 = []CodeSample{
		{`
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
}`, 1}}

	// SampleCodeG404 - weak random number
	SampleCodeG404 = []CodeSample{
		{`
package main
import "crypto/rand"
func main() {
	good, _ := rand.Read(nil)
	println(good)
}`, 0}, {`
package main
import "math/rand"
func main() {
	bad := rand.Int()
	println(bad)
}`, 1}, {`
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
}`, 0}}

	// SampleCodeG501 - Blacklisted import MD5
	SampleCodeG501 = []CodeSample{
		{`
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
}`, 1}}

	// SampleCodeG502 - Blacklisted import DES
	SampleCodeG502 = []CodeSample{
		{`
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
}`, 1}}

	// SampleCodeG503 - Blacklisted import RC4
	SampleCodeG503 = []CodeSample{{`
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
}`, 1}}

	// SampleCodeG504 - Blacklisted import CGI
	SampleCodeG504 = []CodeSample{{`
package main
import (
	"net/http/cgi"
	"net/http"
 )
func main() {
	cgi.Serve(http.FileServer(http.Dir("/usr/share/doc")))
}`, 1}}
)
