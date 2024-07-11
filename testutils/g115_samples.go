package testutils

import "github.com/securego/gosec/v2"

var SampleCodeG115 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint32 = math.MaxUint32
    b := int32(a)
    fmt.Println(b)
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint16 = math.MaxUint16
    b := int32(a)
    fmt.Println(b)
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint32 = math.MaxUint32
    b := uint16(a)
    fmt.Println(b)
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a int32 = math.MaxInt32
    b := int16(a)
    fmt.Println(b)
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a int16 = math.MaxInt16
    b := int32(a)
    fmt.Println(b)
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a int32 = math.MaxInt32
    b := uint32(a)
    fmt.Println(b)
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint = math.MaxUint
    b := int16(a)
    fmt.Println(b)
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint = math.MaxUint
    b := int64(a)
    fmt.Println(b)
}
	`}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
	"fmt"
	"math"
)

func main() {
	var a uint = math.MaxUint
	// #nosec G115
	b := int64(a)
	fmt.Println(b)
}
		`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
	"fmt"
	"math"
)

func main() {
    var a uint = math.MaxUint
	// #nosec G115
    b := int64(a)
    fmt.Println(b)
}
	`, `
package main

func ExampleFunction() {
}
`,
	}, 0, gosec.NewConfig()},
}
