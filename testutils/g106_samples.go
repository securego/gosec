package testutils

import "github.com/securego/gosec/v2"

var (
	// SampleCodeG106 - ssh InsecureIgnoreHostKey
	SampleCodeG106 = []CodeSample{
		{[]string{`
package main

import (
	"golang.org/x/crypto/ssh"
)

func main() {
		_ =  ssh.InsecureIgnoreHostKey()
}
`}, 1, gosec.NewConfig()},
	}
)
