package testutils

import "github.com/securego/gosec/v2"

// #nosec - This file intentionally contains bidirectional Unicode characters
// for testing trojan source detection.　The G116 rule scans the entire file content　(not just AST nodes)
// because trojan source attacks work by manipulating　visual representation of code through bidirectional
// text control characters, which can appear in comments, strings or anywhere in the source file.
// Without this #nosec exclusion, gosec would detect these test samples as actual vulnerabilities.
var (
	// SampleCodeG116 - TrojanSource code snippets
	SampleCodeG116 = []CodeSample{
		{[]string{`
package main

import "fmt"

func main() {
	// This comment contains bidirectional unicode: access‮⁦ granted⁩‭
	isAdmin := false
	fmt.Println("Access status:", isAdmin)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Trojan source with RLO character
	accessLevel := "user"
	// Actually assigns "nimda" due to bidi chars: accessLevel = "‮nimda"
	if accessLevel == "admin" {
		fmt.Println("Access granted")
	}
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// String with bidirectional override
	username := "admin‮ ⁦Check if admin⁩ ⁦"
	password := "secret"
	fmt.Println(username, password)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains LRI (Left-to-Right Isolate) U+2066
	comment := "Safe comment ⁦with hidden text⁩"
	fmt.Println(comment)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains RLI (Right-to-Left Isolate) U+2067
	message := "Normal text ⁧hidden⁩"
	fmt.Println(message)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains FSI (First Strong Isolate) U+2068
	text := "Text with ⁨hidden content⁩"
	fmt.Println(text)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains LRE (Left-to-Right Embedding) U+202A
	embedded := "Text with ‪embedded‬ content"
	fmt.Println(embedded)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains RLE (Right-to-Left Embedding) U+202B
	rtlEmbedded := "Text with ‫embedded‬ content"
	fmt.Println(rtlEmbedded)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains PDF (Pop Directional Formatting) U+202C
	formatted := "Text with ‬formatting"
	fmt.Println(formatted)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains LRO (Left-to-Right Override) U+202D
	override := "Text ‭override"
	fmt.Println(override)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains RLO (Right-to-Left Override) U+202E
	rloText := "Text ‮override"
	fmt.Println(rloText)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains RLM (Right-to-Left Mark) U+200F
	marked := "Text ‏marked"
	fmt.Println(marked)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Contains LRM (Left-to-Right Mark) U+200E
	lrmText := "Text ‎marked"
	fmt.Println(lrmText)
}
`}, 1, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

// Safe code without bidirectional characters
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Username:", username)
	fmt.Println("Password:", password)
}
`}, 0, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

// Normal comment with regular text
func main() {
	// This is a safe comment
	isAdmin := true
	if isAdmin {
		fmt.Println("Access granted")
	}
}
`}, 0, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func main() {
	// Regular ASCII characters only
	message := "Hello, World!"
	fmt.Println(message)
}
`}, 0, gosec.NewConfig()},
		{[]string{`
package main

import "fmt"

func authenticateUser(username, password string) bool {
	// Normal authentication logic
	if username == "admin" && password == "secret" {
		return true
	}
	return false
}

func main() {
	result := authenticateUser("user", "pass")
	fmt.Println("Authenticated:", result)
}
`}, 0, gosec.NewConfig()},
	}
)
