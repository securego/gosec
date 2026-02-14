package taint_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTaint(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Taint Suite")
}
