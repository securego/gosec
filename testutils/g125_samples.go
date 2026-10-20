package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG125 - unescaped elements passed to url.JoinPath
var SampleCodeG125 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	base := "https://example.com/api"
	full, err := url.JoinPath(base, os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	u, err := url.Parse("https://example.com")
	if err != nil {
		panic(err)
	}
	joined := u.JoinPath(os.Args[1])
	fmt.Println(joined)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	full, err := url.JoinPath("https://example.com", "user/"+os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	full, err := url.JoinPath("https://example.com", url.QueryEscape(os.Args[1]))
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	neturl "net/url"
	"os"
)

func main() {
	full, err := neturl.JoinPath("https://example.com", os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	var u url.URL
	u.JoinPath(os.Args[1])
	fmt.Println(u)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	first, err := url.JoinPath("https://example.com", os.Args[1])
	if err != nil {
		panic(err)
	}
	second, err := url.JoinPath(first, os.Args[2])
	if err != nil {
		panic(err)
	}
	fmt.Println(second)
}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

type client struct {
	base *url.URL
}

func main() {
	c := &client{base: &url.URL{Scheme: "https", Host: "example.com"}}
	c.base.JoinPath(os.Args[1])
	fmt.Println(c.base)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
)

func main() {
	full, err := url.JoinPath("https://example.com", "users", "42")
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	full, err := url.JoinPath("https://example.com", url.PathEscape(os.Args[1]))
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	u, err := url.Parse("https://example.com")
	if err != nil {
		panic(err)
	}
	joined := u.JoinPath(url.PathEscape(os.Args[1]))
	fmt.Println(joined)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
	"os"
)

func main() {
	first, err := url.JoinPath("https://example.com", "user-"+url.PathEscape(os.Args[1]))
	if err != nil {
		panic(err)
	}
	second, err := url.JoinPath(first, url.PathEscape(os.Args[1])+"-suffix")
	if err != nil {
		panic(err)
	}
	fmt.Println(second)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/url"
)

const apiVersion = "v1"

func main() {
	full, err := url.JoinPath("https://example.com", apiVersion, "users")
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	neturl "net/url"
	"os"
)

func main() {
	full, err := neturl.JoinPath("https://example.com", neturl.PathEscape(os.Args[1]))
	if err != nil {
		panic(err)
	}
	fmt.Println(full)
}
`}, 0, gosec.NewConfig()},
}
