package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG112 - potential slowloris attack
var SampleCodeG112 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
	})
	err := (&http.Server{
		Addr: ":1234",
	}).ListenAndServe()
	if err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"time"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
	})
	server := &http.Server{
		Addr:              ":1234",
		ReadHeaderTimeout: 3 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"time"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
	})
	server := &http.Server{
		Addr:              ":1234",
		ReadTimeout:  	   1 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"sync"
)

type Server struct {
	hs  *http.Server
	mux *http.ServeMux
	mu  sync.Mutex
}

func New(listenAddr string) *Server {
	mux := http.NewServeMux()

	return &Server{
	hs: &http.Server{ // #nosec G112 - Not publicly exposed
		Addr:    listenAddr,
		Handler: mux,
	},
	mux: mux,
	mu:  sync.Mutex{},
	}
}

func main() {
	fmt.Print("test")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"sync"
)

type Server struct {
	hs  *http.Server
	mux *http.ServeMux
	mu  sync.Mutex
}

func New(listenAddr string) *Server {
	mux := http.NewServeMux()

	return &Server{
	hs: &http.Server{ //gosec:disable G112 - Not publicly exposed
		Addr:    listenAddr,
		Handler: mux,
	},
	mux: mux,
	mu:  sync.Mutex{},
	}
}

func main() {
	fmt.Print("test")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	server := &http.Server{Addr: ":1234"}
	server.ReadHeaderTimeout = 3 * time.Second
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	var server = http.Server{Addr: ":1234"}
	server.ReadTimeout = time.Second
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	server := &http.Server{Addr: ":1234"}
	server.WriteTimeout = 3 * time.Second
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	public := &http.Server{Addr: ":1234"}
	internal := &http.Server{Addr: ":5678"}
	internal.ReadHeaderTimeout = 3 * time.Second
	go func() { _ = internal.ListenAndServe() }()
	if err := public.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	server := &http.Server{Addr: ":1234"}
	server.ReadHeaderTimeout = 3 * time.Second
	server = &http.Server{Addr: ":5678"}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "net/http"

func main() {
	server := &http.Server{
		Addr:              ":1234",
		ReadHeaderTimeout: 0,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "net/http"

func main() {
	server := &http.Server{Addr: ":1234"}
	server.ReadTimeout = 0
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr:              ":1234",
		ReadHeaderTimeout: 0,
		ReadTimeout:       5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

func serve(timeout time.Duration) error {
	server := &http.Server{
		Addr:              ":1234",
		ReadHeaderTimeout: timeout,
	}
	return server.ListenAndServe()
}

func main() {
	if err := serve(3 * time.Second); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

type app struct {
	server *http.Server
}

func (a *app) start() error {
	a.server = &http.Server{Addr: ":1234"}
	a.server.ReadHeaderTimeout = 3 * time.Second
	return a.server.ListenAndServe()
}

func main() {
	if err := (&app{}).start(); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

type app struct {
	server http.Server
}

func main() {
	var a app
	a.server = http.Server{Addr: ":1234"}
	a.server.ReadTimeout = 3 * time.Second
	if err := a.server.ListenAndServe(); err != nil {
		panic(err)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
	"time"
)

type app struct {
	public   *http.Server
	internal *http.Server
}

func (a *app) start() error {
	a.public = &http.Server{Addr: ":1234"}
	a.internal = &http.Server{Addr: ":5678"}
	a.internal.ReadHeaderTimeout = 3 * time.Second
	go func() { _ = a.internal.ListenAndServe() }()
	return a.public.ListenAndServe()
}

func main() {
	if err := (&app{}).start(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "net/http"

type app struct {
	server *http.Server
}

func (a *app) start() error {
	a.server = &http.Server{Addr: ":1234"}
	a.server.ReadHeaderTimeout = 0
	return a.server.ListenAndServe()
}

func main() {
	if err := (&app{}).start(); err != nil {
		panic(err)
	}
}
`}, 1, gosec.NewConfig()},
}
