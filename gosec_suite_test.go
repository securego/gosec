package gosec_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGosec(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gosec Suite")
}
