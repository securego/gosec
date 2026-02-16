package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG121 - Unsafe CORS bypass patterns via CrossOriginProtection
var SampleCodeG121 = []CodeSample{
	// Vulnerable: overbroad root bypass
	{[]string{`
package main

import "net/http"

func setup() {
	var cop http.CrossOriginProtection
	cop.AddInsecureBypassPattern("/")
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: overbroad wildcard bypass
	{[]string{`
package main

import "net/http"

func setup() {
	var cop http.CrossOriginProtection
	cop.AddInsecureBypassPattern("/*")
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: user-controlled bypass pattern from request data
	{[]string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = w
	var cop http.CrossOriginProtection
	pattern := r.URL.Query().Get("bypass")
	cop.AddInsecureBypassPattern(pattern)
}
`}, 1, gosec.NewConfig()},

	// Safe: narrow static bypass
	{[]string{`
package main

import "net/http"

func setup() {
	var cop http.CrossOriginProtection
	cop.AddInsecureBypassPattern("/healthz")
}
`}, 0, gosec.NewConfig()},

	// Safe: multiple narrow static bypasses
	{[]string{`
package main

import "net/http"

func setup() {
	var cop http.CrossOriginProtection
	cop.AddInsecureBypassPattern("/status")
	cop.AddInsecureBypassPattern("/metrics")
}
`}, 0, gosec.NewConfig()},
}
