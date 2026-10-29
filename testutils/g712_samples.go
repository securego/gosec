package testutils

import gosec "github.com/securego/gosec/v2"

// SampleCodeG712 contains samples for detecting XPath injection.
var SampleCodeG712 = []CodeSample{
	// Positive: request form value flows through fmt.Sprintf into an XPath expression.
	{
		Code: []string{`
package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/antchfx/xmlquery"
)

func xpathInjection(r *http.Request) {
	doc, _ := xmlquery.Parse(strings.NewReader("<root><user name=\"a\" id=\"1\"/></root>"))
	q := fmt.Sprintf("//user[@name='%s']", r.FormValue("name"))
	_ = xmlquery.Find(doc, q)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: query parameter is concatenated inline into the XPath expression.
	{
		Code: []string{`
package main

import (
	"net/http"
	"strings"

	"github.com/antchfx/xmlquery"
)

func xpathInjectionInline(r *http.Request) {
	doc, _ := xmlquery.Parse(strings.NewReader("<root><user name=\"a\" id=\"1\"/></root>"))
	_ = xmlquery.FindOne(doc, "//user[@id='"+r.URL.Query().Get("id")+"']")
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: constant XPath expression passed to Find.
	{
		Code: []string{`
package main

import (
	"strings"

	"github.com/antchfx/xmlquery"
)

func xpathInjectionConstantFind() {
	doc, _ := xmlquery.Parse(strings.NewReader("<root><user name=\"a\" id=\"1\"/></root>"))
	_ = xmlquery.Find(doc, "//user[@name='a']")
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: constant XPath expression passed to FindOne.
	{
		Code: []string{`
package main

import (
	"strings"

	"github.com/antchfx/xmlquery"
)

func xpathInjectionConstantFindOne() {
	doc, _ := xmlquery.Parse(strings.NewReader("<root><user name=\"a\" id=\"1\"/></root>"))
	_ = xmlquery.FindOne(doc, "//user[@id='1']")
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
}
