package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG710 - Open redirect via taint analysis
var SampleCodeG710 = []CodeSample{
	// Positive: query parameter flows directly into http.Redirect URL.
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	http.Redirect(w, r, target, http.StatusFound)
}
`}, 1, gosec.NewConfig()},

	// Positive: form value concatenated into a redirect target.
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	dest := r.FormValue("redirect")
	http.Redirect(w, r, "/proxy?to="+dest, http.StatusSeeOther)
}
`}, 1, gosec.NewConfig()},

	// Negative: redirect to a constant URL — never tainted.
	{[]string{`
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
`}, 0, gosec.NewConfig()},

	// Negative: redirect target derived from numeric conversion of user input
	// (strconv.Atoi sanitizer strips any redirect payload from the string).
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d", id), http.StatusFound)
}
`}, 0, gosec.NewConfig()},
}
