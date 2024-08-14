package testutils

import "github.com/securego/gosec/v2"

var (
	// SampleCodeG407 - Use of hardcoded nonce/IV
	SampleCodeG407 = []CodeSample{
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

}`}, 1, gosec.NewConfig()},
	}

	// SampleCodeG407b - Use of hardcoded nonce/IV
	SampleCodeG407b = []CodeSample{
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
	}

	// SampleCodeG407c - Use of hardcoded nonce/IV
	SampleCodeG407c = []CodeSample{
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
	}

	// SampleCodeG407d - Use of hardcoded nonce/IV
	SampleCodeG407d = []CodeSample{
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
	}

	// SampleCodeG407e - Use of hardcoded nonce/IV
	SampleCodeG407e = []CodeSample{
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
	}

	// SampleCodeG407f - Use of hardcoded nonce/IV
	SampleCodeG407f = []CodeSample{
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
	}

	// SampleCodeG407g - Use of hardcoded nonce/IV
	SampleCodeG407g = []CodeSample{
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
	}

	// SampleCodeG407h - Use of hardcoded nonce/IV
	SampleCodeG407h = []CodeSample{
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
	}

	// SampleCodeG407I - Use of hardcoded nonce/IV
	SampleCodeG407i = []CodeSample{
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
	}

	// SampleCodeG407j - Use of hardcoded nonce/IV
	SampleCodeG407j = []CodeSample{
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
	}

	// SampleCodeG407k - Use of hardcoded nonce/IV
	SampleCodeG407k = []CodeSample{
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
	}

	// SampleCodeG407l - Use of hardcoded nonce/IV
	SampleCodeG407l = []CodeSample{
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
	}

	// SampleCodeG407m - Use of hardcoded nonce/IV
	SampleCodeG407m = []CodeSample{
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
	}

	// SampleCodeG407n - Use of hardcoded nonce/IV
	SampleCodeG407n = []CodeSample{
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
	}

	// SampleCodeG407o - Use of hardcoded nonce/IV
	SampleCodeG407o = []CodeSample{
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
	}
)
