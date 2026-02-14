package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG408 - SSH PublicKeyCallback stateful misuse
var SampleCodeG408 = []CodeSample{
	// Vulnerable: Direct capture and write to outer variable
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

var lastKey ssh.PublicKey

func setupServer() {
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		lastKey = key
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Struct field write via captured struct
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

type Server struct {
	currentKey ssh.PublicKey
}

func setupServer() {
	srv := &Server{}
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		srv.currentKey = key
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Map update with captured map
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	keyMap := make(map[string]ssh.PublicKey)
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyMap[conn.User()] = key
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Slice modification
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	keys := make([]ssh.PublicKey, 10)
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keys[0] = key
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Safe: No captured variables modified
	{[]string{`
package main

import (
	"errors"
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if isAuthorized(key) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("unauthorized")
	}
	_ = config
}

func isAuthorized(key ssh.PublicKey) bool {
	return true
}
`}, 0, gosec.NewConfig()},

	// Safe: Storing key data in Permissions.Extensions (correct pattern)
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{
			Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			},
		}, nil
	}
	_ = config
}
`}, 0, gosec.NewConfig()},

	// Safe: Only reading captured variables
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	authorizedKeys := map[string]bool{
		"ssh-rsa AAA...": true,
	}
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		keyStr := string(key.Marshal())
		if authorizedKeys[keyStr] {
			return &ssh.Permissions{}, nil
		}
		return nil, nil
	}
	_ = config
}
`}, 0, gosec.NewConfig()},

	// Safe: No closure captures at all
	{[]string{`
package main

import (
	"errors"
	"golang.org/x/crypto/ssh"
)

func setupServer() {
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = checkKey
	_ = config
}

func checkKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return nil, errors.New("not implemented")
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: Nested struct field modification
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

type Session struct {
	Auth struct {
		LastKey ssh.PublicKey
	}
}

func setupServer() {
	session := &Session{}
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		session.Auth.LastKey = key
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Safe: Using nosec to suppress
	{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

var lastKey ssh.PublicKey

func setupServer() {
	config := &ssh.ServerConfig{}
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		lastKey = key // #nosec G408
		return &ssh.Permissions{}, nil
	}
	_ = config
}
`}, 0, gosec.NewConfig()},
}
