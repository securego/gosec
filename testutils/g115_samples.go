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
	{[]string{
		`
package main

import (
	"fmt"
	"math"
)

type Uint uint

func main() {
    var a uint8 = math.MaxUint8
    b := Uint(a)
    fmt.Println(b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
	"fmt"
)

func main() {
    var a byte = '\xff'
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
)

func main() {
    var a int8 = -1
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

type CustomType int

func main() {
    var a uint = math.MaxUint
    b := CustomType(a)
    fmt.Println(b)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
	"fmt"
)

func main() {
    a := []int{1,2,3}
    b := uint32(len(a))
    fmt.Println(b)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
)

func main() {
        a := "A\xFF"
        b := int64(a[0])
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
)

func main() {
        var a uint8 = 13
        b := int(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
)

func main() {
        const a int64 = 13
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < math.MinInt32 {
            panic("out of range")
        }
        if a > math.MaxInt32 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < math.MinInt32 && a > math.MaxInt32 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < math.MinInt32 || a > math.MaxInt32 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < math.MinInt64 || a > math.MaxInt32 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
)

func main() {
        var a int32 = math.MaxInt32
        if a < math.MinInt32 && a > math.MaxInt32 {
            panic("out of range")
        }
        var b int64 = int64(a) * 2
        c := int32(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "strconv"
)

func main() {
        var a string = "13"
        b, _ := strconv.ParseInt(a, 10, 32)
        c := int32(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "strconv"
)

func main() {
        var a string = "13"
        b, _ := strconv.ParseUint(a, 10, 8)
        c := uint8(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "strconv"
)

func main() {
        var a string = "13"
        b, _ := strconv.ParseUint(a, 10, 16)
        c := int(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "strconv"
)

func main() {
        var a string = "13"
        b, _ := strconv.ParseUint(a, 10, 31)
        c := int32(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "strconv"
)

func main() {
        var a string = "13"
        b, _ := strconv.ParseInt(a, 10, 8)
        c := uint8(b)
        fmt.Printf("%d\n", c)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < 0 {
            panic("out of range")
        }
        if a > math.MaxUint32 {
            panic("out of range")
        }
        b := uint32(a)
        fmt.Printf("%d\n", b)
}
`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a < 0 {
            panic("out of range")
        }
        b := uint32(a)
        fmt.Printf("%d\n", b)
}
`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "math"
)

func foo(x int) uint32 {
        if x < 0 {
            return 0
        }
        if x > math.MaxUint32 {
            return math.MaxUint32
        }
        return uint32(x)
}
`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "math"
)

func foo(items []string) uint32 {
        x := len(items)
        if x > math.MaxUint32 {
            return math.MaxUint32
        }
        return uint32(x)
}
`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "math"
)

func foo(items []string) uint32 {
        x := cap(items)
        if x > math.MaxUint32 {
            return math.MaxUint32
        }
        return uint32(x)
}
`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "math"
)

func foo(items []string) uint32 {
        x := len(items)
        if x < math.MaxUint32 {
            return uint32(x)
        }
        return math.MaxUint32
}
`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a >= math.MinInt32 && a <= math.MaxInt32 {
            b := int32(a)
            fmt.Printf("%d\n", b)
        }
        panic("out of range")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a >= math.MinInt32 && a <= math.MaxInt32 {
            b := int32(a)
            fmt.Printf("%d\n", b)
        }
        panic("out of range")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if !(a >= math.MinInt32) && a > math.MaxInt32 {
            b := int32(a)
            fmt.Printf("%d\n", b)
        }
        panic("out of range")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if !(a >= math.MinInt32) || a > math.MaxInt32 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if math.MinInt32 <= a && math.MaxInt32 >= a {
            b := int32(a)
            fmt.Printf("%d\n", b)
        }
        panic("out of range")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a == 3 || a == 4 {
            b := int32(a)
            fmt.Printf("%d\n", b)
        }
        panic("out of range")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import (
        "fmt"
        "math/rand"
)

func main() {
        a := rand.Int63()
        if a != 3 || a != 4 {
            panic("out of range")
        }
        b := int32(a)
        fmt.Printf("%d\n", b)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import "unsafe"

func main() {
	i := uintptr(123)
	p := unsafe.Pointer(i)
	_ = p
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
        package main

        import (
            "fmt"
            "math/rand"
        )

        func main() {
            a := rand.Int63()
            if a >= 0 {
                panic("no positivity allowed")
            }
            b := uint64(-a)
            fmt.Printf("%d\n", b)
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

        type CustomStruct struct {
            Value int
        }

        func main() {
            results := CustomStruct{Value: 0}
            if results.Value < math.MinInt32 || results.Value > math.MaxInt32 {
                panic("value out of range for int32")
            }
            convertedValue := int32(results.Value)

            fmt.Println(convertedValue)
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

        type CustomStruct struct {
            Value int
        }

        func main() {
            results := CustomStruct{Value: 0}
            if results.Value >= math.MinInt32 && results.Value <= math.MaxInt32 {
                convertedValue := int32(results.Value)
                fmt.Println(convertedValue)
            }
            panic("value out of range for int32")
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

        type CustomStruct struct {
            Value int
        }

        func main() {
            results := CustomStruct{Value: 0}
            if results.Value < math.MinInt32 || results.Value > math.MaxInt32 {
                panic("value out of range for int32")
            }
            // checked value is decremented by 1 before conversion which is unsafe
            convertedValue := int32(results.Value-1)

            fmt.Println(convertedValue)
        }
        `,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
        package main

        import (
                "fmt"
                "math"
                "math/rand"
        )

        func main() {
            a := rand.Int63()
            if a < math.MinInt32 || a > math.MaxInt32 {
                panic("out of range")
            }
            // checked value is incremented by 1 before conversion which is unsafe
            b := int32(a+1)
            fmt.Printf("%d\n", b)
        }
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
        package main

        import (
                "fmt"
                "strconv"
        )

        func main() {
            a, err := strconv.ParseUint("100", 10, 16)
            if err != nil {
              panic("parse error")
            }
            b := uint16(a)
            fmt.Printf("%d\n", b)
        }
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func sneakyNEQ(a int) uint {
	if a == 3 || a != 4 {
		return uint(a)
	}
	panic("not supported")
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main

func checkThenArithmetic(a int) uint {
	if a >= 0 && a < 10 {
		return uint(a + 1)
	}
	panic("not supported")
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func binaryTruncation(a int) uint16 {
	return uint16(a & 0xffff)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func builtinMin(a, b int) uint16 {
	if a < 0 || a > 100 || b < 0 || b > 100 {
		return 0
	}
	result := min(a, b)
	return uint16(result)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func loopIndices(myArr []string) {
	for i, _ := range myArr {
		_ = uint64(i)
	}
	for i := 0; i < 10; i++ {
		_ = uint64(i)
	}
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func bitShifting(u32 uint32) uint8 {
	return uint8(u32 >> 24)
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import "time"

func unixMilli() uint64 {
	return uint64(time.Now().UnixMilli())
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

import "math"

type innerStruct struct {
	u32 *uint32
}
type nestedStruct struct {
	i *innerStruct
}

func nestedPointerCheck(n nestedStruct) {
	if *n.i.u32 > math.MaxInt32 {
		panic("out of range")
	} else {
		i32 := int32(*n.i.u32)
		_ = i32
	}
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func f(_ uint64) {}

func nestedSwitch(x int32) {
	switch {
	case x > 0:
		switch {
		case true:
			f(uint64(x))
		}
	}
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main

func constantArithmetic(someLen int) {
	const multiple = 4
	_ = uint8(multiple - (int(someLen) % multiple))
}
	`,
	}, 0, gosec.NewConfig()},
	{[]string{
		`
package main
import "fmt"
func main() {
	x := int64(-1)
	y := uint64(x)
	fmt.Println(y)
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{
		`
package main
import "math"
func main() {
	u := uint64(math.MaxUint64)
	i := int64(u)
	_ = i
}
	`,
	}, 1, gosec.NewConfig()},
	{[]string{`
package main
func checkGEQ(x int) uint64 {
	if x >= 10 {
		return uint64(x)
	}
	return 0
}
func checkGTR(x int) uint64 {
	if x > 10 {
		return uint64(x)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func checkNEQ(x int) uint64 {
	if x != 10 {
		return 0
	}
	// x == 10 here
	return uint64(x)
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func addProp(x uint8) uint16 {
	// x is 0..255. y = x + 10 is 10..265.
	return uint16(x + 10)
}
func subProp(x uint8) uint16 {
	y := int(x)
	if y > 20 && y < 100 {
		return uint16(y - 10)
	}
	return 0
}
func subFlipped(x int) uint16 {
	if x > 0 && x < 10 {
		return uint16(20 - x)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func andOp(x int) uint16 {
	return uint16(x & 0xFF)
}
func shrOp(x int) uint16 {
	if x >= 0 && x <= 0xFFFF {
		y := uint16(x)
		return uint16(y >> 4)
	}
	return 0
    
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
import "strconv"
func parseVariants(s string) {
	v8, _ := strconv.ParseInt(s, 10, 8)
	_ = int8(v8)

	v64, _ := strconv.ParseInt(s, 10, 64)
	_ = int64(v64)

	u32, _ := strconv.ParseUint(s, 10, 32)
	_ = uint32(u32)

	u64, _ := strconv.ParseUint(s, 10, 64)
	_ = uint64(u64)
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func remOp(x int) uint16 {
	y := x % 10
	if y >= 0 {
		return uint16(y)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func negProp(y int) uint16 {
	if y > -10 && y < 0 {
		x := -y
		return uint16(x)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func minMaxProp(a, b int) uint16 {
	if a > 0 && a < 10 && b > 0 && b < 20 {
		x := min(a, b)
		y := max(a, b)
		return uint16(x + y)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func subFlippedBound(y int) uint16 {
	if (100 - y) > 0 && (100 - y) < 50 {
		return uint16(100 - y) 
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func remSigned(y int) uint16 {
	x := y % 10 // range -9..9
	if x >= 0 {
		return uint16(x)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func bitwiseProp(y int) uint16 {
	if (y & 0xFF) < 100 {
		return uint16(y & 0xFF)
	}
	return 0
}
func shiftProp(y uint16) uint8 {
	if (y >> 4) < 10 {
		return uint8(y >> 4)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
import "strconv"
func parse64(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v < 1000 {
		return uint32(v)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func addPropRel(x int) uint16 {
	if (x + 10) < 100 && (x + 10) > 0 {
		return uint16(x + 10)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func negExplicit(y int) uint16 {
	if y > -10 && y < -5 {
		x := -y
		return uint16(x)
	}
	return 0
}
func subFlippedExplicit(y int) uint16 {
	if y > 60 && y < 90 {
		return uint16(100 - y)
	}
	return 0
}
func addExplicit(y int) uint16 {
    if y > 10 && y < 20 {
        return uint16(y + 100)
    }
    return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func minMaxCheck(a, b int) uint16 {
	if a > 0 && a < 10 && b > 10 && b < 20 {
		return uint16(min(a, b) + max(a, b))
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
import "strconv"
func parseExplicit(s string) {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v > 0 && v < 100 {
		_ = uint8(v)
	}
	u, _ := strconv.ParseUint(s, 10, 64)
	if u < 100 {
		_ = uint8(u)
	}
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func remExplicit(y int) uint16 {
	x := y % 10
	if x >= 0 && x < 10 {
		return uint16(x)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func andPropCheck(x int) uint8 {
	if x > 1000 {
		return uint8(x & 0x7F) // x & 0x7F is [0, 127]
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func shrPropCheck(x int) uint8 {
	if x > 0 && x < 4000 {
		return uint8(x >> 4) // 4000 >> 4 = 250
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func remPropCheck(x int) uint8 {
	if x > -100 {
		y := x % 10 // range [-9, 9]
		if y >= 0 {
			return uint8(y)
		}
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func shrFallback(x uint16) uint8 {
	return uint8(x >> 8) // computeRange fallback: uint16.Max >> 8 = 255 (fits uint8)
}
func remSignedFallback(x int) int8 {
	return int8(x % 10) // computeRange fallback: [-9, 9] fits int8
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func shrPropComplex(x int) uint8 {
	if x > 0 && x < 1000 {
		y := x >> 2 // y is [0, 250]
		return uint8(y)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func remPropComplex(x int) int8 {
	if x > -100 && x < 100 {
		y := x % 10 // y is [-9, 9]
		return int8(y)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func mulProp(x int) uint8 {
	if x >= 0 && x < 20 {
		return uint8(x * 10) // [0, 190] -> fits in uint8 (255)
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func quoProp(x int) uint8 {
	if x >= 0 && x < 2000 {
		return uint8(x / 10) // [0, 199] -> fits in uint8
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func mulProp(x int) int8 {
	if x < 0 && x > -10 {
		return int8(x * 10) // [-100, 0] -> fits in int8
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func quoProp(x int) int8 {
	if x < 0 && x > -1000 {
		return int8(x / 10) // [-99, 0] -> fits in int8
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func mulOverflow(x int) uint8 {
	if x >= 0 && x < 30 {
		return uint8(x * 10) // [10, 290] -> overflows uint8
	}
	return 0
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main
func mulProp(x int) uint8 {
	if x < 0 && x > -10 {
		return uint8(x * 10) // [-90, 0] -> negative
	}
	return 0
}
    `}, 1, gosec.NewConfig()},
	{[]string{`
package main
func quoProp(x int) uint8 {
	if x < 0 && x > -1000 {
		return uint8(x / 10) // [-99, 0] -> negative
	}
	return 0
}
	`}, 1, gosec.NewConfig()},
	{[]string{`
package main
func quoNegProp(x int) uint8 {
	if x > -100 && x < -10 {
		return uint8(x / -5) // [-99, -11] / -5 -> [2, 19] -> fits in uint8
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func mulNegProp(x int) uint8 {
	if x > -10 && x < 0 {
		return uint8(x * -5) // [-9, -1] * -5 -> [5, 45] -> fits in uint8
	}
	return 0
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func coverageProp(x int) {
	// SUB val - x
	{
		a := 10
		b := 100 - a // 90
		_ = int8(b)
	}
	// MUL neg defined
	{
		a := 10
		b := a * -5 // -50
		_ = int8(b)
	}
	// QUO neg defined
	{
		a := 100
		b := a / -2 // -50
		_ = int8(b)
	}
	// REM neg
	{
		a := -50
		b := a % 10
		_ = int8(b)
	}
	// Square (isSameOrRelated)
	{
		a := 10
		b := a * a // 100
		_ = int8(b)
	}
    _ = x
}
	`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func shrProp(x uint8) uint8 {
    return x >> 1
}
	`}, 0, gosec.NewConfig()},
}
