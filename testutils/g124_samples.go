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
	// Negative: negating a known false value enables Secure
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := false
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   !x,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: negating a known false value enables HttpOnly
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := false
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: !x,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: nested negations preserve a known true value
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := true
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   !!x,
		HttpOnly: !!x,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Positive: negating a known true value disables Secure
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := true
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   !x,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: negating a known true value disables HttpOnly
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := true
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: !x,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: an unknown negated Secure value is not assumed safe
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := r.TLS == nil
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   !x,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: an unknown negated HttpOnly value is not assumed safe
	{
		Code: []string{`
package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	x := r.TLS == nil
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: !x,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
}
