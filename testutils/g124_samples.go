package testutils

import gosec "github.com/securego/gosec/v2"

// SampleCodeG124 contains samples for detecting insecure HTTP cookie configuration.
var SampleCodeG124 = []CodeSample{
	// Positive: cookie with no security attributes set
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:  "session",
		Value: "abc123",
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: Secure=false explicitly
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: missing HttpOnly
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: all security attributes set correctly
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: all security attributes set correctly with LaxMode
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
}
