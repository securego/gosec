package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG113 - HTTP request smuggling vulnerabilities
var SampleCodeG113 = []CodeSample{
	// Pattern: Conflicting TE and CL headers - VULNERABLE
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Length", "100")
	w.Write([]byte("response body"))
}
`}, 1, gosec.NewConfig()},

	// Pattern: Conflicting headers (reverse order) - VULNERABLE
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "100")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Write([]byte("response body"))
}
`}, 1, gosec.NewConfig()},

	// Pattern: Conflicting headers via Header() variable - VULNERABLE
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Transfer-Encoding", "chunked")
	header.Set("Content-Length", "50")
	w.Write([]byte("data"))
}
`}, 1, gosec.NewConfig()},

	// Safe: Only Content-Length header
	{[]string{`
package main

import (
	"net/http"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "100")
	w.Write([]byte("response body"))
}
`}, 0, gosec.NewConfig()},

	// Safe: Only Transfer-Encoding header
	{[]string{`
package main

import (
	"net/http"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Write([]byte("response body"))
}
`}, 0, gosec.NewConfig()},

	// Safe: Other headers only
	{[]string{`
package main

import (
	"net/http"
)

func anotherSafeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte("{}"))
}
`}, 0, gosec.NewConfig()},
}
