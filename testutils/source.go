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
)
