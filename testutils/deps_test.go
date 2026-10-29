package testutils

import (
	// Keep test-only dependencies used by G117 and taint analyzer samples in go.mod/go.sum.
	_ "github.com/BurntSushi/toml"
	_ "github.com/antchfx/xmlquery"
	_ "github.com/dop251/goja"
	_ "github.com/go-ldap/ldap/v3"
	_ "github.com/robertkrimen/otto"
	_ "github.com/traefik/yaegi"
)
