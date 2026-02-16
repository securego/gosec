package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG120 - Unbounded form parsing in HTTP handlers
var SampleCodeG120 = []CodeSample{
	// Vulnerable: ParseForm without body size limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.ParseForm()
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: FormValue implicitly triggers ParseForm without body size limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.FormValue("q")
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: ParseMultipartForm without body size limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.ParseMultipartForm(32 << 20)
}
`}, 1, gosec.NewConfig()},

	// Safe: request body bounded with MaxBytesReader before ParseForm
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	_ = r.ParseForm()
}
`}, 0, gosec.NewConfig()},

	// Safe: request body bounded with MaxBytesReader before FormValue
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	_ = r.FormValue("name")
}
`}, 0, gosec.NewConfig()},
}
