package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG407 - Use of hardcoded nonce/IV
var SampleCodeG407 = []CodeSample{
	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesOFB := cipher.NewOFB(block, []byte("ILoveMyNonceAlot"))
	var output = make([]byte, 16)
	aesOFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

}
`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func encrypt(nonce []byte) {
	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesOFB := cipher.NewOFB(block, nonce)
	var output = make([]byte, 16)
	aesOFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))
}

func main() {

	var nonce = []byte("ILoveMyNonceAlot")
	encrypt(nonce)
}
`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesOFB := cipher.NewOFB(block, []byte("ILoveMyNonceAlot")) // #nosec G407
	var output = make([]byte, 16)
	aesOFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

}

`}, 0, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher( []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)

	cipherText := aesGCM.Seal(nil, func() []byte {
		if true {
			return []byte("ILoveMyNonce")
		} else {
			return []byte("IDont'Love..")
		}
	}(), []byte("My secret message"), nil) // #nosec G407
	fmt.Println(string(cipherText))

	cipherText, _ = aesGCM.Open(nil, func() []byte {
		if true {
			return []byte("ILoveMyNonce")
		} else {
			return []byte("IDont'Love..")
		}
	}(), cipherText, nil) // #nosec G407

	fmt.Println(string(cipherText))
}
`}, 0, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesOFB := cipher.NewOFB(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	var output = make([]byte, 16)
	aesOFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

}`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCTR := cipher.NewCTR(block, []byte("ILoveMyNonceAlot"))
	var output = make([]byte, 16)
	aesCTR.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

}`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCTR := cipher.NewCTR(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	var output = make([]byte, 16)
	aesCTR.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

}
`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)

	cipherText := aesGCM.Seal(nil, []byte("ILoveMyNonce"), []byte("My secret message"), nil)
	fmt.Println(string(cipherText))
	cipherText, _ = aesGCM.Open(nil, []byte("ILoveMyNonce"), cipherText, nil)
	fmt.Println(string(cipherText))
}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)
	cipherText := aesGCM.Seal(nil, []byte{}, []byte("My secret message"), nil)
	fmt.Println(string(cipherText))

	cipherText, _ = aesGCM.Open(nil, []byte{}, cipherText, nil)
	fmt.Println(string(cipherText))
}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)

	cipherText := aesGCM.Seal(nil, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("My secret message"), nil)
	fmt.Println(string(cipherText))

	cipherText, _ = aesGCM.Open(nil, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, cipherText, nil)
	fmt.Println(string(cipherText))
}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher( []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)

	cipherText := aesGCM.Seal(nil, func() []byte {
		if true {
			return []byte("ILoveMyNonce")
		} else {
			return []byte("IDont'Love..")
		}
	}(), []byte("My secret message"), nil)
	fmt.Println(string(cipherText))

	cipherText, _ = aesGCM.Open(nil, func() []byte {
		if true {
			return []byte("ILoveMyNonce")
		} else {
			return []byte("IDont'Love..")
		}
	}(), cipherText, nil)

	fmt.Println(string(cipherText))
}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)

	cipherText := aesGCM.Seal(nil, func() []byte {
		if true {
			return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		} else {
			return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		}
	}(), []byte("My secret message"), nil)
	fmt.Println(string(cipherText))

	cipherText, _ = aesGCM.Open(nil, func() []byte {
		if true {
			return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		} else {
			return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
		}
	}(), cipherText, nil)
	fmt.Println(string(cipherText))
}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)
	cipheredText := aesGCM.Seal(nil, func() []byte { return []byte("ILoveMyNonce") }(), []byte("My secret message"), nil)
	fmt.Println(string(cipheredText))
	cipheredText, _ = aesGCM.Open(nil, func() []byte { return []byte("ILoveMyNonce") }(), cipheredText, nil)
	fmt.Println(string(cipheredText))

}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)
	cipheredText := aesGCM.Seal(nil, func() []byte { return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} }(), []byte("My secret message"), nil)
	fmt.Println(string(cipheredText))
	cipheredText, _ = aesGCM.Open(nil, func() []byte { return []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1} }(), cipheredText, nil)
	fmt.Println(string(cipheredText))

}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCFB := cipher.NewCFBEncrypter(block, []byte("ILoveMyNonceAlot"))
	var output = make([]byte, 16)
	aesCFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))
	aesCFB = cipher.NewCFBDecrypter(block, []byte("ILoveMyNonceAlot"))
	aesCFB.XORKeyStream(output, output)
	fmt.Println(string(output))

}`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCFB := cipher.NewCFBEncrypter(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	var output = make([]byte, 16)
	aesCFB.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))
	aesCFB = cipher.NewCFBDecrypter(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCFB.XORKeyStream(output, output)
	fmt.Println(string(output))

}`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCBC := cipher.NewCBCEncrypter(block, []byte("ILoveMyNonceAlot"))

	var output = make([]byte, 16)
	aesCBC.CryptBlocks(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

	aesCBC = cipher.NewCBCDecrypter(block, []byte("ILoveMyNonceAlot"))
	aesCBC.CryptBlocks(output, output)
	fmt.Println(string(output))

}`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCBC := cipher.NewCBCEncrypter(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})

	var output = make([]byte, 16)
	aesCBC.CryptBlocks(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))

	aesCBC = cipher.NewCBCDecrypter(block, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCBC.CryptBlocks(output, output)
	fmt.Println(string(output))

}
`}, 2, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	var nonce = []byte("ILoveMyNonce")
	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)
	fmt.Println(string(aesGCM.Seal(nil, nonce, []byte("My secret message"), nil)))
}
`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {

	var nonce = []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCTR := cipher.NewCTR(block, nonce)
	var output = make([]byte, 16)
	aesCTR.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))
}
`}, 1, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func coolFunc(size int) []byte{
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

func main() {

	var nonce = coolFunc(16)
	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesCTR := cipher.NewCTR(block, nonce)
	var output = make([]byte, 16)
	aesCTR.XORKeyStream(output, []byte("Very Cool thing!"))
	fmt.Println(string(output))
}
`}, 0, gosec.NewConfig()},

	{[]string{`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

var nonce = []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

func main() {

	block, _ := aes.NewCipher([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
	aesGCM, _ := cipher.NewGCM(block)
	cipherText := aesGCM.Seal(nil, nonce, []byte("My secret message"), nil)
	fmt.Println(string(cipherText))

}
`}, 1, gosec.NewConfig()},
}
