package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG118 - Context propagation failures that may leak goroutines/resources
var SampleCodeG118 = []CodeSample{
	// Vulnerable: goroutine uses context.Background while request context exists
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = ctx
	go func() {
		child, _ := context.WithTimeout(context.Background(), time.Second)
		_ = child
	}()
}
`}, 2, gosec.NewConfig()},

	// Vulnerable: cancel function from context.WithTimeout is never called
	{[]string{`
package main

import (
	"context"
	"time"
)

func work(ctx context.Context) {
	child, _ := context.WithTimeout(ctx, time.Second)
	_ = child
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with blocking call and no ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func run(ctx context.Context) {
	for {
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: complex infinite multi-block loop without ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func complexInfinite(ctx context.Context, ch <-chan int) {
	_ = ctx
	for {
		select {
		case <-ch:
			time.Sleep(time.Millisecond)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: goroutine propagates request context and checks cancellation
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	go func(ctx2 context.Context) {
		for {
			select {
			case <-ctx2.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}(ctx)
}
`}, 0, gosec.NewConfig()},

	// Safe: cancel is always called
	{[]string{`
package main

import (
	"context"
	"time"
)

func work(ctx context.Context) {
	child, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = child
}
`}, 0, gosec.NewConfig()},

	// Safe: loop has explicit ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: bounded loop with blocking call (finite by condition)
	{[]string{`
package main

import (
	"context"
	"time"
)

func bounded(ctx context.Context) {
	_ = ctx
	for i := 0; i < 3; i++ {
		time.Sleep(time.Millisecond)
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: complex loop with explicit non-context exit path
	{[]string{`
package main

import (
	"context"
	"time"
)

func worker(ctx context.Context, max int) {
	_ = ctx
	i := 0
	for {
		if i >= max {
			break
		}
		time.Sleep(time.Millisecond)
		i++
	}
}
`}, 0, gosec.NewConfig()},
}
