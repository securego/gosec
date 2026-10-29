package testutils

import gosec "github.com/securego/gosec/v2"

// SampleCodeG709 contains samples for detecting unsafe deserialization of untrusted data.
var SampleCodeG709 = []CodeSample{
	// Positive: gob.NewDecoder with tainted reader from user input
	{
		Code: []string{`
package main

import (
	"encoding/gob"
	"net/http"
	"strings"
)

type User struct {
	Name string
	Role string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	dec := gob.NewDecoder(strings.NewReader(data))
	var user User
	dec.Decode(&user)
	_ = user
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: xml.NewDecoder with tainted reader from user input
	{
		Code: []string{`
package main

import (
	"encoding/xml"
	"net/http"
	"strings"
)

type Payload struct {
	XMLName xml.Name
	Data    string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("xml")
	dec := xml.NewDecoder(strings.NewReader(data))
	var p Payload
	dec.Decode(&p)
	_ = p
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Positive: xml.Unmarshal with tainted bytes from user input
	{
		Code: []string{`
package main

import (
	"encoding/xml"
	"net/http"
)

type Config struct {
	Key   string
	Value string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("payload")
	var cfg Config
	xml.Unmarshal([]byte(data), &cfg)
	_ = cfg
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: gob.NewDecoder from a local file (not an HTTP source)
	{
		Code: []string{`
package main

import (
	"encoding/gob"
	"os"
)

type User struct {
	Name string
}

func main() {
	f, _ := os.Open("data.gob")
	defer f.Close()
	var user User
	dec := gob.NewDecoder(f)
	dec.Decode(&user)
	_ = user
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Negative: encoding/json (not flagged — too common, low risk)
	{
		Code: []string{`
package main

import (
	"encoding/json"
	"net/http"
)

type User struct {
	Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	var user User
	json.Unmarshal([]byte(data), &user)
	_ = user
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
	// Positive: mirrors an entry function with an io.Reader parameter.
	// The gob branch is detected; the xml branch over a bare string parameter is
	// not detected because a plain string parameter is not a taint source in the engine.
	{
		Code: []string{`
package main

import (
	"encoding/gob"
	"encoding/xml"
	"io"
)

func deserialization(flag string, r io.Reader, xmlData string) {
	if flag == "xml" {
		var v interface{}
		_ = xml.Unmarshal([]byte(xmlData), &v)
		return
	}
	var v interface{}
	_ = gob.NewDecoder(r).Decode(&v)
}
`},
		Errors: 1,
		Config: gosec.NewConfig(),
	},
	// Negative: encoding/json is not a G709 sink. Because a plain string parameter
	// is not a taint source, the xml.Unmarshal branch in the sample above is not flagged.
	{
		Code: []string{`
package main

import (
	"encoding/json"
)

func deserializationJSON(data string) {
	var v interface{}
	_ = json.Unmarshal([]byte(data), &v)
}
`},
		Errors: 0,
		Config: gosec.NewConfig(),
	},
}
