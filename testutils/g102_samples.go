package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG102 code snippets for network binding
var SampleCodeG102 = []CodeSample{
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
}
`}, 1, gosec.NewConfig()},
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
}
`}, 1, gosec.NewConfig()},
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
}
`}, 1, gosec.NewConfig()},
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
}
`}, 1, gosec.NewConfig()},
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
}
`}, 1, gosec.NewConfig()},
	// Bind to all networks through the IPv6 unspecified address
	{[]string{`
package main

import (
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", "[::]:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"crypto/tls"
	"log"
)

const addr = "[::]:2000"

func main() {
	l, err := tls.Listen("tcp", addr, &tls.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`}, 1, gosec.NewConfig()},
	// Bind to the IPv6 loopback address only
	{[]string{`
package main

import (
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", "[::1]:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`}, 0, gosec.NewConfig()},
	// Bind to the IPv4 loopback address only
	{[]string{`
package main

import (
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`}, 0, gosec.NewConfig()},
	// Bind to all networks with the port appended to an empty host
	{[]string{`
package main

import (
	"log"
	"net"
)

func listen(port string) {
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}

func main() {
	listen("2000")
}
`}, 1, gosec.NewConfig()},
	// Bind to all networks with the port appended to 0.0.0.0
	{[]string{`
package main

import (
	"crypto/tls"
	"log"
	"os"
)

func main() {
	l, err := tls.Listen("tcp", "0.0.0.0:"+os.Getenv("PORT"), &tls.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`}, 1, gosec.NewConfig()},
	// Bind to all networks through a constant declared in another file
	{[]string{`
package main

import (
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}
`, `
package main

const listenAddr = "[::]:2000"
`}, 1, gosec.NewConfig()},
	// Bind to the loopback address with the port appended
	{[]string{`
package main

import (
	"log"
	"net"
)

func listen(port string) {
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}

func main() {
	listen("2000")
}
`}, 0, gosec.NewConfig()},
	// Bind to a host that is not known statically
	{[]string{`
package main

import (
	"log"
	"net"
)

func listen(host, port string) {
	l, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}

func main() {
	listen("localhost", "2000")
}
`}, 0, gosec.NewConfig()},
}
