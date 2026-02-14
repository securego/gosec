package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG408 - SSH PublicKeyCallback stateful misuse
var SampleCodeG408 = []CodeSample{
	// Vulnerable: Direct capture and write to outer variable
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

var lastKey PublicKey

func setupServer() {
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		lastKey = key
		return &Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Struct field write via captured struct
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

type Server struct {
	currentKey PublicKey
}

func setupServer() {
	srv := &Server{}
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		srv.currentKey = key
		return &Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Map update with captured map
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	keyMap := make(map[string]PublicKey)
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		keyMap[conn.User()] = key
		return &Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Slice modification
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	keys := make([]PublicKey, 10)
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		keys[0] = key
		return &Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: Nested struct field modification
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

type Session struct {
	Auth struct {
		LastKey PublicKey
	}
}

func setupServer() {
	session := &Session{}
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		session.Auth.LastKey = key
		return &Permissions{}, nil
	}
	_ = config
}
`}, 1, gosec.NewConfig()},

	// Safe: No captured variables modified
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		if isAuthorized(key) {
			return &Permissions{}, nil
		}
		return nil, nil
	}
	_ = config
}

func isAuthorized(key PublicKey) bool {
	return true
}
`}, 0, gosec.NewConfig()},

	// Safe: Storing key data in Permissions.Extensions (correct pattern)
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		return &Permissions{
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

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	authorizedKeys := map[string]bool{
		"ssh-rsa AAA...": true,
	}
	config := &ServerConfig{}
	config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
		keyStr := string(key.Marshal())
		if authorizedKeys[keyStr] {
			return &Permissions{}, nil
		}
		return nil, nil
	}
	_ = config
}
`}, 0, gosec.NewConfig()},

	// Safe: No closure captures at all
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func setupServer() {
	config := &ServerConfig{}
	config.PublicKeyCallback = checkKey
	_ = config
}

func checkKey(conn ConnMetadata, key PublicKey) (*Permissions, error) {
	return nil, nil
}
`}, 0, gosec.NewConfig()},

	// Safe: Module-level function (not closure)
	{[]string{`
package main

// Mock ssh types for testing
type PublicKey interface {
	Marshal() []byte
}

type ConnMetadata interface {
	User() string
}

type Permissions struct {
	Extensions map[string]string
}

type ServerConfig struct {
	PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}

func authenticateKey(conn ConnMetadata, key PublicKey) (*Permissions, error) {
	// This is a module-level function, not a closure
	return &Permissions{}, nil
}

func setupServer() {
	config := &ServerConfig{}
	config.PublicKeyCallback = authenticateKey
	_ = config
}
`}, 0, gosec.NewConfig()},
}
