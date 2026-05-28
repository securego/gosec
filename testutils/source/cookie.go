package main

import (
	"net/http"
)

func main() {
	// G118: missing both Secure and HttpOnly
	_ = http.Cookie{
		Name:  "session",
		Value: "abc123",
	}

	// G118: missing Secure
	_ = http.Cookie{
		Name:     "session",
		Value:    "abc123",
		HttpOnly: true,
	}

	// G118: missing HttpOnly
	_ = http.Cookie{
		Name:   "session",
		Value:  "abc123",
		Secure: true,
	}

	// OK: both flags set
	_ = http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Secure:   true,
		HttpOnly: true,
	}
}
