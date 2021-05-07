package cwe_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCwe(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cwe Suite")
}
