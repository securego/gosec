package gas_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestGas(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gas Suite")
}
