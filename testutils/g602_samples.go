package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG602 - Slice access out of bounds
var SampleCodeG602 = []CodeSample{
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)

	fmt.Println(s[:3])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)

	fmt.Println(s[3:])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[:17])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[:16])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[5:17])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 4)

	fmt.Println(s[3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 4)

	fmt.Println(s[5])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)
	s = make([]byte, 3)

	fmt.Println(s[:3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)

	fmt.Println(s[:3])
	fmt.Println(s[3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)

	fmt.Println(s[:5])
	fmt.Println(s[7])

}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)
	x := s[:2]
	y := x[:10]
	fmt.Println(y)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]int, 0, 4)
	doStuff(s)
}

func doStuff(x []int) {
	newSlice := x[:10]
	fmt.Println(newSlice)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]int, 0, 30)
	doStuff(s)
	x := make([]int, 20)
	y := x[10:]
	doStuff(y)
	z := y[5:]
	doStuff(z)
}

func doStuff(x []int) {
	newSlice := x[:10]
	fmt.Println(newSlice)
	newSlice2 := x[:6]
	fmt.Println(newSlice2)
}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	testMap := make(map[string]any, 0)
	testMap["test1"] = map[string]interface{}{
	"test2": map[string]interface{}{
			"value": 0,
		},
	}
	fmt.Println(testMap)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		fmt.Println(s[0])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		switch s[0] {
		case 0:
			fmt.Println("zero")
			return
		default:
			fmt.Println(s[0])
			return
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		switch s[0] {
		case 0:
			b := true
			if b == true {
				// Should work for many-levels of nesting when the condition is not on the target slice
				fmt.Println(s[0])
			}
			return
		default:
			fmt.Println(s[0])
			return
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		if len(s) > 1 {
			fmt.Println(s[1])
		}
		fmt.Println(s[0])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
s := make([]byte, 2)
fmt.Println(s[1])
s = make([]byte, 0)
fmt.Println(s[1])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		if len(s) > 4 {
			fmt.Println(s[3])
		} else {
			// Should error
			fmt.Println(s[2])
		}
		fmt.Println(s[0])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		fmt.Println("fake test")
	}
	fmt.Println(s[0])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 16)
	for i := 0; i < 17; i++ {
		s = append(s, i)
	}
	if len(s) < 16 {
		fmt.Println(s[10:16])
	} else {
		fmt.Println(s[3:18])
	}
	fmt.Println(s[0])
	for i := range s {
		fmt.Println(s[i])
	}
}

`}, 0, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	s := make([]int, 16)
	for i := 10; i < 17; i++ {
        s[i]=i
	}
}

`}, 1, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	var s []int
	for i := 10; i < 17; i++ {
        s[i]=i
	}
}

`}, 1, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	s := make([]int,5, 16)
	for i := 1; i < 6; i++ {
        s[i]=i
	}
}

`}, 1, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	var s [20]int
	for i := 10; i < 17; i++ {
        s[i]=i
	}
}`}, 0, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	var s [20]int
	for i := 1; i < len(s); i++ {
        s[i]=i
	}
}

`}, 0, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	var s [20]int
	for i := 1; i <= len(s); i++ {
        s[i]=i
	}
}

`}, 1, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	var s [20]int
	for i := 18; i <= 22; i++ {
        s[i]=i
	}
}

`}, 1, gosec.NewConfig()},
	{[]string{`
package main
func main() {
	args := []any{"1"}
	switch len(args) - 1 {
	case 1:
		_ = args[1]
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	value := "1234567890"
	weight := []int{2, 3, 4, 5, 6, 7}
	wLen := len(weight)
	l := len(value) - 1
	addr := make([]any, 7)
	sum := 0
	weight[2] = 3
	for i := l; i >= 0; i-- {
		v := int(value[i] - '0')
		if v < 0 || v > 9 {
			fmt.Println("invalid number at column", i+1)
			break
		}
		addr[2] = v
		sum += v * weight[(l-i)%wLen]
	}
	fmt.Println(sum)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func pairwise(list []any) {
	for i := 0; i < len(list)-1; i += 2 {
		// Safe: i < len-1 implies i+1 < len
		fmt.Printf("%v %v\n", list[i], list[i+1])
	}
}

func main() {
	// Calls with both even and odd lengths (and empty) to exercise the path
	pairwise([]any{"a", "b", "c", "d"})
	pairwise([]any{"x", "y", "z"})
	pairwise([]any{})
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

type Handler struct{}

func (h *Handler) HandleArgs(list []any) {
	for i := 0; i < len(list)-1; i += 2 {
		fmt.Printf("%v %v\n", list[i], list[i+1])
	}
}

func main() {
	// Empty main: no call to HandleArgs, mimicking library code or unreachable for constant prop
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func safeTriples(list []int) {
	for i := 0; i < len(list)-2; i += 3 {
		fmt.Println(list[i], list[i+1], list[i+2])
	}
}

func main() {
	safeTriples([]int{1,2,3,4,5,6,7})
	safeTriples([]int{1,2,3,4,5})
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func pairwise(list []any) {
	for i := 0; i+1 < len(list); i += 2 {
		// Safe: i+1 < len implies i < len-1
		fmt.Printf("%v %v\n", list[i], list[i+1])
	}
}

func main() {
	// Calls with both even and odd lengths (and empty) to exercise the path
	pairwise([]any{"a", "b", "c", "d"})
	pairwise([]any{"x", "y", "z"})
	pairwise([]any{})
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0, 4)
	// Extending length up to capacity is valid
	x := s[:3]
	fmt.Println(x)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0, 4)
	// 3-index slice exceeding capacity
	x := s[:2:5]
	fmt.Println(x)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0, 10)
	// 3-index slice within capacity
	x := s[2:5:8]
	fmt.Println(x)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 4)
	for i := range 3 {
		x := s[i+2]
		fmt.Println(x)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 5)
	for i := range 3 {
		x := s[i+2]
		fmt.Println(x)
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 2)
	for i := 0; i < 3; i++ {
		x := s[i+2]
		fmt.Println(x)
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main
import "fmt"
func main() {
	s := make([]byte, 2)
	i := 0
	// decomposeIndex should handle i + 1 + 2 = i + 3
	fmt.Println(s[i+1+2])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main
import "fmt"
func main() {
	s := make([]byte, 5)
	for i := 0; i+1 < len(s); i++ {
		// i+1 < 5 => i < 4. Max i = 3. i+1 = 4. s[4] is safe.
		fmt.Println(s[i+1])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
import "fmt"
func main() {
	var a [10]int
	idx := 12
	fmt.Println(a[idx])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main
import "fmt"
func main() {
	s := make([]byte, 4)
	if 5 < len(s) {
		fmt.Println(s[4])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func main() {
	var a [10]int
	k := 11
	_ = a[:5:k]
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main
import "fmt"
func main() {
	s := make([]int, 5)
	idx := -1
	fmt.Println(s[idx])
}
`}, 1, gosec.NewConfig()},
	// Issue #1495: G602 false positive for array element access with coexisting slice expression
	{[]string{`
package main
import (
	"log/slog"
	"runtime"
	"time"
)
func main() {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	r := slog.NewRecord(time.Now(), slog.LevelError, "test", pcs[0])
	_ = r
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func main() {
	var buf [4]byte
	copy(buf[:], []byte("test"))
	_ = buf[0]
	_ = buf[1]
	_ = buf[2]
	_ = buf[3]
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func main() {
	var buf [2]byte
	copy(buf[:], []byte("ab"))
	idx := 3
	_ = buf[idx]
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main
func doWork(s []int) {}
func main() {
	var arr [5]int
	doWork(arr[:])
	_ = arr[0]
	_ = arr[4]
}
`}, 0, gosec.NewConfig()},
	// Issue #1525: G602 false positive for array index in range-over-array loops
	{[]string{`
package main
func main() {
	var arr [8]int
	for i := range arr {
		arr[i] = i
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main
func main() {
	var arr [8]int
	for i := range arr {
		_ = arr[i+1]
	}
}
`}, 1, gosec.NewConfig()},
	// Issue #1545: G602 false positive on range-over-array indexing into same-size array
	{[]string{`
package main

func main() {
	ranged := [1]int{1}
	var accessed [1]*int

	for i, r := range ranged {
		accessed[i] = &r
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

func main() {
	ranged := [2]int{1, 2}
	var accessed [1]*int

	for i, r := range ranged {
		accessed[i] = &r
	}
}
`}, 1, gosec.NewConfig()},
	// Issue #1727: G602 not reported for a constant index equal to the length
	// asserted by an equality guard (index == len is always out of range)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[4])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)-1 == 1 {
		fmt.Println(s[1])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else {
		fmt.Println(s[1])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)-1 == 1 {
	} else {
		fmt.Println(s[0])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 0 {
		fmt.Println(s[0])
	}
}
`}, 1, gosec.NewConfig()},
	// Reversed operand order: the constant sits on the left of the guard, which
	// extractBinOpBound handles in its binop.X arm. The asserted length has to
	// be honoured in the "then" branch and distrusted in the "else" branch just
	// as it is when the constant is on the right.
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if 3 == len(s) {
		fmt.Println(s[3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if 3 == len(s) {
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if 3 == len(s) {
	} else {
		fmt.Println(s[1])
	}
}
`}, 1, gosec.NewConfig()},
	// A positive constant offset on the compared expression: "len(s) + 1 == 4"
	// asserts a length of 3, so index 3 is out of range and index 2 is not.
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)+1 == 4 {
		fmt.Println(s[3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)+1 == 4 {
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// An "else if" chain: the inner guard owns its own "then" successor, so the
	// length it asserts still clears an index inside that length.
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else if len(s) == 5 {
		fmt.Println(s[4])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else if len(s) == 5 {
		fmt.Println(s[5])
	}
}
`}, 1, gosec.NewConfig()},
	// A nested equality guard inside the outer "else" branch: the nested guard
	// is authoritative for the block it opens, so an index inside the length it
	// asserts is cleared even though the outer branch asserts nothing.
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else {
		if len(s) == 1 {
			fmt.Println(s[0])
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else {
		if len(s) == 1 {
			fmt.Println(s[1])
		}
	}
}
`}, 1, gosec.NewConfig()},

	// Equality guards must validate the actual subslice bounds, only in the then branch.
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[1:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if 3 == len(s) {
		fmt.Println(s[:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)-1 == 2 {
		fmt.Println(s[:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s)+1 == 4 {
		fmt.Println(s[:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[:3:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[:4])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[:3:4])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else {
		fmt.Println(s[:3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
	} else {
		fmt.Println(s[:3:3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[1:])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[3:3])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func check(n int) {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[1:n])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func check(n int) {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[n:3])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func check(n int) {
	s := make([]int, 0)
	if len(s) == 3 {
		fmt.Println(s[:3:n])
	}
}
`}, 1, gosec.NewConfig()},

	// Issue #1753: G602 performs no bounds checking at all on the direct
	// result of append() -- the IndexAddr base-type dispatch never reaches
	// any bounds-checking path for a *ssa.Call. A statically-determinable
	// append() growth (literal args) must now be tracked like make()/composite
	// literals are, so an out-of-bounds constant index is flagged.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 10)
	fmt.Println(s[6])
}
`}, 1, gosec.NewConfig()},
	// Same append()-grown slice, but the access is properly guarded by a
	// satisfied len() equality check matching the asserted length -- must
	// not be flagged.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 10)
	if len(s) == 1 {
		fmt.Println(s[0])
	}
}
`}, 0, gosec.NewConfig()},
	// Cross-variable guard mismatch from #1753's own reproduction: a guard on
	// one slice's len() must not "protect" a completely different slice's
	// out-of-bounds index.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 10)

	s2 := []int{10}
	if len(s) == 3 {
		fmt.Println(s2[6])
	}
}
`}, 1, gosec.NewConfig()},
	// A spread of a slice whose length is not statically determinable (e.g.
	// spreading a function parameter) must not be treated as adding any
	// guaranteed growth -- no new false positive from guessing an unknown
	// length.
	{[]string{`
package main

import "fmt"

func f(other []int) {
	s := []int{}
	s = append(s, other...)
	fmt.Println(s[6])
}

func main() {
	f([]int{1, 2, 3})
}
`}, 0, gosec.NewConfig()},
	// #1753's own equality-guard case: the constant index (6) falls outside
	// the length asserted by the guard (3), so it's flagged under the same
	// trust model #1746/#1749 already established for make()/composite-literal
	// slices -- an append()-derived slice must reach the same conclusion.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 10)
	if len(s) == 3 {
		fmt.Println(s[6])
	}
}
`}, 1, gosec.NewConfig()},
	// #1753's own inequality-guard case: a "len(s) >= N" guard clears the
	// access unconditionally under the pre-existing (unrelated to append())
	// upperUnbounded/unbounded correlation behavior. Locks in the current
	// trust model for an append()-derived slice.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 10)
	if len(s) >= 3 {
		fmt.Println(s[6])
	}
}
`}, 0, gosec.NewConfig()},
	// #1753 follow-up: append(s) with zero variadic arguments must still be
	// tracked as zero guaranteed growth, not silently dropped (the SSA
	// builder lowers this to append(s, nil...), a *ssa.Const, not a
	// *ssa.Slice).
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{1}
	t := append(s)
	fmt.Println(t[3])
}
`}, 1, gosec.NewConfig()},
	// append() inside a loop with an in-bounds index must not be flagged --
	// the most common real-world append() shape.
	{[]string{`
package main

import "fmt"

func main() {
	var s []int
	for i := 0; i < 3; i++ {
		s = append(s, i)
		fmt.Println(s[i])
	}
}
`}, 0, gosec.NewConfig()},
	// Chained append() calls: the recursion must follow the growth of a
	// nested append() result, not just a single level.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(append(s, 1), 2)
	fmt.Println(s[5])
}
`}, 1, gosec.NewConfig()},
	// A multi-element literal append() must count every added element, not
	// just one.
	{[]string{`
package main

import "fmt"

func main() {
	s := []int{}
	s = append(s, 1, 2, 3)
	fmt.Println(s[5])
}
`}, 1, gosec.NewConfig()},
}
