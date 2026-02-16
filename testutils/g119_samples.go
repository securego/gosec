package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG119 - Unsafe redirect policy that may leak sensitive headers
var SampleCodeG119 = []CodeSample{
	// Vulnerable: directly copies all headers from previous request
	{[]string{`
package main

import "net/http"

func client() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header = via[len(via)-1].Header.Clone()
			return nil
		},
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: explicitly re-adds Authorization header in redirect callback
	{[]string{`
package main

import "net/http"

func client() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Set("Authorization", "Bearer token")
			return nil
		},
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: explicitly re-adds Cookie header in redirect callback
	{[]string{`
package main

import "net/http"

func client() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Add("Cookie", "a=b")
			return nil
		},
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: stop redirects
	{[]string{`
package main

import (
	"errors"
	"net/http"
)

func client() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			_ = req
			_ = via
			return errors.New("stop")
		},
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: only sets non-sensitive header
	{[]string{`
package main

import "net/http"

func client() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			_ = via
			req.Header.Set("X-Trace-ID", "123")
			return nil
		},
	}
}
`}, 0, gosec.NewConfig()},
}
