package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG708 - Server-side template injection via text/template
var SampleCodeG708 = []CodeSample{
	// Positive: user input flows into Template.Parse (SSTI - critical)
	{[]string{`
package main

import (
	"net/http"
	"text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userTmpl := r.URL.Query().Get("tmpl")
	t, _ := template.New("page").Parse(userTmpl)
	t.Execute(w, nil)
}
`}, 1, gosec.NewConfig()},

	// Positive: user input rendered via text/template Execute to ResponseWriter (XSS)
	{[]string{`
package main

import (
	"net/http"
	"text/template"
)

var tmpl = template.Must(template.New("page").Parse(` + "`<h1>Hello {{.}}</h1>`" + `))

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	tmpl.Execute(w, name)
}
`}, 1, gosec.NewConfig()},

	// Positive: ExecuteTemplate with tainted data to ResponseWriter
	{[]string{`
package main

import (
	"net/http"
	"text/template"
)

var tmpl = template.Must(template.New("").Parse(` + "`{{define \"greeting\"}}Hello {{.}}{{end}}`" + `))

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	tmpl.ExecuteTemplate(w, "greeting", name)
}
`}, 1, gosec.NewConfig()},

	// Negative: html/template is safe (auto-escapes) — should NOT trigger
	{[]string{`
package main

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("page").Parse(` + "`<h1>Hello {{.}}</h1>`" + `))

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	tmpl.Execute(w, name)
}
`}, 0, gosec.NewConfig()},

	// Negative: text/template Execute to non-HTTP writer (e.g. os.Stdout) — no XSS risk
	{[]string{`
package main

import (
	"os"
	"text/template"
)

func main() {
	tmpl := template.Must(template.New("page").Parse(` + "`Hello {{.}}`" + `))
	tmpl.Execute(os.Stdout, "World")
}
`}, 0, gosec.NewConfig()},

	// Negative: sanitized input via html.EscapeString before Execute
	{[]string{`
package main

import (
	"html"
	"net/http"
	"text/template"
)

var tmpl = template.Must(template.New("page").Parse(` + "`<h1>Hello {{.}}</h1>`" + `))

func handler(w http.ResponseWriter, r *http.Request) {
	safe := html.EscapeString(r.FormValue("name"))
	tmpl.Execute(w, safe)
}
`}, 0, gosec.NewConfig()},
}
