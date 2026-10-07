package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG203 - Template checks
var SampleCodeG203 = []CodeSample{
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
}
`}, 0, gosec.NewConfig()},
	{[]string{`
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
}
`}, 1, gosec.NewConfig()},
	{[]string{`
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
}
`}, 1, gosec.NewConfig()},
	{[]string{`
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
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// A named constant is as safe as a literal
package main

import (
	"html/template"
	"os"
)

const tmpl = ""

const banner = "<b>Scheduled maintenance tonight</b>"

func main() {
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.HTML(banner),
	}
	t.Execute(os.Stdout, v)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Concatenated literals are constant as well
package main

import (
	"html/template"
	"os"
)

const tmpl = ""

const greeting = "hello"

func main() {
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.HTML("<i>" + greeting + "</i>"),
		"Script":   template.JS("console.log('" + greeting + "')"),
	}
	t.Execute(os.Stdout, v)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Concatenating a variable into a constant is not safe
package main

import (
	"html/template"
	"os"
)

const tmpl = ""

func main() {
	name := os.Getenv("NAME")
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.HTML("<b>" + name + "</b>"),
	}
	t.Execute(os.Stdout, v)
}
`}, 1, gosec.NewConfig()},
}
