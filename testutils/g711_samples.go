package testutils

import gosec "github.com/securego/gosec/v2"

// SampleCodeG711 contains samples for detecting LDAP injection.
var SampleCodeG711 = []CodeSample{
	// Positive: request form value flows through fmt.Sprintf into the LDAP filter.
	{
		Code: []string{`
package main

import (
	"fmt"
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
)

var ldapConn = &ldap.Conn{}

func ldapInjection(r *http.Request) {
	v := r.FormValue("emp")
	filter := fmt.Sprintf("(employeeNumber=%s)", v)
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
	_, _ = ldapConn.Search(req)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: query parameter is concatenated inline into the LDAP filter.
	{
		Code: []string{`
package main

import (
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
)

var ldapConn = &ldap.Conn{}

func ldapInjectionInline(r *http.Request) {
	user := r.URL.Query().Get("user")
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(uid="+user+")", []string{"dn"}, nil)
	_, _ = ldapConn.Search(req)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: constant LDAP filter.
	{
		Code: []string{`
package main

import (
	ldap "github.com/go-ldap/ldap/v3"
)

func ldapInjectionConstant() {
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(employeeNumber=1001)", []string{"dn"}, nil)
	_ = req
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: filter is sanitized with ldap.EscapeFilter.
	{
		Code: []string{`
package main

import (
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
)

func ldapInjectionEscaped(r *http.Request) {
	v := ldap.EscapeFilter(r.FormValue("emp"))
	filter := "(employeeNumber=" + v + ")"
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
	_ = req
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Positive: ldap.EscapeDN escapes RFC 4514 DN metacharacters but preserves
	// the filter metacharacters * ( ), so it does not sanitize filter injection
	// and this path must still report G711.
	{
		Code: []string{`
package main

import (
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
)

func ldapInjectionEscapedDN(r *http.Request) {
	v := ldap.EscapeDN(r.FormValue("emp"))
	filter := "(uid=" + v + ")"
	req := ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"dn"}, nil)
	_ = req
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
}
