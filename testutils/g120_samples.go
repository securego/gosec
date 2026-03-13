package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG120 - Unbounded multipart form parsing in HTTP handlers.
// Only ParseMultipartForm is flagged because ParseForm, FormValue, and
// PostFormValue already enforce a built-in 10 MiB body limit.
var SampleCodeG120 = []CodeSample{
	// Vulnerable: ParseMultipartForm without body size limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.ParseMultipartForm(32 << 20)
}
`}, 1, gosec.NewConfig()},

	// Safe: ParseForm has a built-in 10 MiB limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.ParseForm()
}
`}, 0, gosec.NewConfig()},

	// Safe: FormValue implicitly calls ParseForm which has a built-in 10 MiB limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.FormValue("q")
}
`}, 0, gosec.NewConfig()},

	// Safe: PostFormValue has a built-in 10 MiB limit
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r.PostFormValue("q")
}
`}, 0, gosec.NewConfig()},

	// ParseMultipartForm with MaxBytesReader still flags because the taint
	// engine tracks the request parameter, not the body field. Users who
	// apply MaxBytesReader can suppress with #nosec G120.
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	_ = r.ParseMultipartForm(32 << 20)
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: ParseMultipartForm in a separate helper function (issue #1600)
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	processUpload(r)
}

func processUpload(r *http.Request) {
	_ = r.ParseMultipartForm(32 << 20)
}
`}, 1, gosec.NewConfig()},

	// Safe: ParseForm in a separate helper function has built-in limit
	{[]string{`
package main

import "net/http"

func fooHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = formParser(r)
	_, _ = w.Write([]byte("foo"))
}

func formParser(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return r.FormValue("varName"), nil
}
`}, 0, gosec.NewConfig()},
}
