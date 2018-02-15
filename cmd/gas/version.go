package main

import (
	"fmt"
)

const (
	major = 2
	minor = 0
	patch = 0
	tag   = ""
)

// Version builds a semantic version
func Version() string {
	version := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	if tag != "" {
		version = fmt.Sprintf("%s-%s", version, tag)
	}
	return version
}
