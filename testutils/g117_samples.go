// testutils/g117_samples.go
package testutils

import "github.com/securego/gosec/v2"

var SampleCodeG117 = []CodeSample{
	// Positive: json.Marshal on sensitive field
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: json.MarshalIndent on sensitive json tag key
	{[]string{`
package main

import "encoding/json"

type Config struct {
	APIKey *string ` + "`json:\"api_key\"`" + `
}

func main() {
	_, _ = json.MarshalIndent(Config{}, "", "  ")
}
`}, 1, gosec.NewConfig()},

	// Positive: Encoder.Encode on []byte secret
	{[]string{`
package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	PrivateKey []byte ` + "`json:\"private_key\"`" + `
}

func main() {
	_ = json.NewEncoder(os.Stdout).Encode(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: match on field name even if json key is non-sensitive
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string ` + "`json:\"text_field\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: match on JSON key with safe field name
	{[]string{`
package main

import "encoding/json"

type Config struct {
	SafeField string ` + "`json:\"api_key\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: match on both field and json key
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Token string ` + "`json:\"auth_token\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: snake/hyphen variants in json key
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Key string ` + "`json:\"access-key\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: empty json tag name falls back to field name
	// Positive: empty json tag part falls back to field name
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Secret string ` + "`json:\",omitempty\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: plural forms
	// Positive: plural forms
	{[]string{`
package main

import "encoding/json"

type Config struct {
	ApiTokens []string
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	{[]string{`
package main

import "encoding/json"

type Config struct {
	RefreshTokens []string ` + "`json:\"refresh_tokens\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	{[]string{`
package main

import "encoding/json"

type Config struct {
	AccessTokens []*string
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	{[]string{`
package main

import "encoding/json"

type Config struct {
	CustomSecret string ` + "`json:\"my_custom_secret\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, func() gosec.Config {
		cfg := gosec.NewConfig()
		cfg.Set("G117", map[string]interface{}{
			"pattern": "(?i)custom[_-]?secret",
		})
		return cfg
	}()},

	// Positive: pointer to struct argument
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.Marshal(&Config{})
}
`}, 1, gosec.NewConfig()},

	// Positive: slice of structs argument
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.Marshal([]Config{{}})
}
`}, 1, gosec.NewConfig()},

	// Positive: map with struct value argument
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.Marshal(map[string]Config{"x": {}})
}
`}, 1, gosec.NewConfig()},

	// Negative: sensitive field is never marshaled to JSON
	{[]string{`
package main

type Config struct {
	Password string
}

func main() {}
`}, 0, gosec.NewConfig()},

	// Negative (issue #1527): anonymous struct used for template execution only
	{[]string{`
package main

import (
	"bytes"
	"text/template"
)

func main() {
	t := template.Must(template.New("x").Parse("{{.Username}}"))
	var tpl bytes.Buffer
	_ = t.Execute(&tpl, struct {
		Username string
		Password string
	}{})
}
`}, 0, gosec.NewConfig()},

	// Negative (issue #1527): env tags should not imply JSON serialization
	{[]string{`
package main

type AppConfig struct {
	ApiSecret string ` + "`env:\"API_SECRET\"`" + `
}

func main() {}
`}, 0, gosec.NewConfig()},

	// Negative: json:"-" (omitted)
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string ` + "`json:\"-\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: both field name and json key non-sensitive
	// Negative: both field name and JSON key non-sensitive
	{[]string{`
package main

import "encoding/json"

type Config struct {
	UserID string ` + "`json:\"user_id\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: marshal of plain string does not involve struct field analysis
	{[]string{`
package main

import "encoding/json"

func main() {
	_, _ = json.Marshal("api_key")
}
`}, 0, gosec.NewConfig()},

	// Negative: unexported field
	{[]string{`
package main

import "encoding/json"

type Config struct {
	password string
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: unexported sensitive field with sensitive json tag is still ignored
	{[]string{`
package main

import "encoding/json"

type Config struct {
	password string ` + "`json:\"password\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: json:"-," means field name "-" (not omitted), and should not match when field name is non-sensitive
	{[]string{`
package main

import "encoding/json"

type Config struct {
	SafeField string ` + "`json:\"-,\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: non-sensitive type (int) even with "token"
	{[]string{`
package main

import "encoding/json"

type Config struct {
	MaxTokens int
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: non-secret plural slice (common FP like redaction placeholders)
	{[]string{`
package main

import "encoding/json"

type Config struct {
	RedactionTokens []string ` + "`json:\"redactionTokens,omitempty\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: grouped fields, only one sensitive (should still flag the sensitive one)
	// Note: we expect 1 issue (for the sensitive field)
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Safe, Password string
}

func main() {
	_, _ = json.Marshal(Config{})
}
`}, 1, gosec.NewConfig()},

	// Suppression: trailing line comment
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.Marshal(Config{}) // #nosec G117
}
`}, 0, gosec.NewConfig()},

	// Suppression: line comment above field
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	// #nosec G117 -- false positive
	_, _ = json.Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Suppression: trailing with justification
	{[]string{`
package main

import "encoding/json"

type Config struct {
	APIKey string ` + "`json:\"api_key\"`" + `
}

func main() {
	_, _ = json.Marshal(Config{}) // #nosec G117 -- public key
}
`}, 0, gosec.NewConfig()},

	// Suppression: MarshalIndent call line
	{[]string{`
package main

import "encoding/json"

type Config struct {
	Password string
}

func main() {
	_, _ = json.MarshalIndent(Config{}, "", "  ") // #nosec G117
}
`}, 0, gosec.NewConfig()},

	// Suppression: Encode call line
	{[]string{`
package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	Password string
}

func main() {
	_ = json.NewEncoder(os.Stdout).Encode(Config{}) // #nosec G117
}
`}, 0, gosec.NewConfig()},

	// Negative: non-JSON function named Marshal
	{[]string{`
package main

type Config struct {
	Password string
}

func Marshal(any) {}

func main() {
	Marshal(Config{})
}
`}, 0, gosec.NewConfig()},

	// Negative: non-encoding/json Encoder type with Encode method
	{[]string{`
package main

type Encoder struct{}

func (Encoder) Encode(any) error { return nil }

type Config struct {
	Password string
}

func main() {
	_ = Encoder{}.Encode(Config{})
}
`}, 0, gosec.NewConfig()},
}
