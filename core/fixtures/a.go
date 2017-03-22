package fixtures

import (
	"fmt"
)

type Test1 struct {
	message string
}

func (t *Test1) Print() {
	fmt.Println(t.message)
}
