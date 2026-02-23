package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG705 - XSS via taint analysis
var SampleCodeG705 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
)

func writeHandler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	w.Write([]byte(data))
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"html"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Safe - escaped output
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello World</h1>")
}
`}, 0, gosec.NewConfig()},
	// Test: json.Marshal sanitizer
	{[]string{`
package main

import (
	"encoding/json"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	jsonData, _ := json.Marshal(data)
	w.Write(jsonData)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	w.Write([]byte(strconv.Itoa(num)))
}
`}, 0, gosec.NewConfig()},
	// Test: context.Context should not propagate taint from *http.Request
	// This is the pattern from PR #1543 — r.Context() passed to a function
	// should not taint the function's return value.
	{[]string{`
package main

import (
	"context"
	"net/http"
)

type service struct{}

func (s *service) GetData(ctx context.Context, id string) ([]byte, error) {
	return []byte("safe data"), nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	svc := &service{}
	data, _ := svc.GetData(r.Context(), "static-id")
	w.Write(data)
}
`}, 0, gosec.NewConfig()},
}
