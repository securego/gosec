package testutils

import gosec "github.com/securego/gosec/v2"

// SampleCodeG713 contains samples for detecting code injection.
var SampleCodeG713 = []CodeSample{
	// Positive: request form value is evaluated by yaegi.
	{
		Code: []string{`
package main

import (
	"net/http"

	"github.com/traefik/yaegi/interp"
)

func codeInjectionEval(r *http.Request) {
	code := r.FormValue("code")
	i := interp.New(interp.Options{})
	_, _ = i.Eval(code)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: query parameter is executed by otto.
	{
		Code: []string{`
package main

import (
	"net/http"

	"github.com/robertkrimen/otto"
)

func codeInjectionOtto(r *http.Request) {
	vm := otto.New()
	_, _ = vm.Run(r.URL.Query().Get("expr"))
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: constant source evaluated by yaegi.
	{
		Code: []string{`
package main

import (
	"github.com/traefik/yaegi/interp"
)

func codeInjectionConstantEval() {
	i := interp.New(interp.Options{})
	_, _ = i.Eval("1 + 1")
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: constant source executed by otto.
	{
		Code: []string{`
package main

import (
	"github.com/robertkrimen/otto"
)

func codeInjectionConstantOtto() {
	vm := otto.New()
	_, _ = vm.Run("1 + 1")
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
}
