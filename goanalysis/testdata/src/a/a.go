package a

import (
	"crypto/md5" // want "G501: \\[CWE-327\\] Blocklisted import crypto/md5: weak cryptographic primitive"
	"fmt"
	"os/exec"
)

func VulnerableFunction() {
	// Test SQL injection - gosec doesn't catch simple string concatenation without database/sql
	query := "SELECT * FROM users WHERE name = '" + getUserInput() + "'"
	_ = query

	// Test G204: Command injection
	cmd := exec.Command("sh", "-c", getUserInput()) // want "G204: \\[CWE-78\\] Subprocess launched with a potential tainted input or cmd arguments"
	_ = cmd

	// Test G401: Weak crypto
	h := md5.New() // want "G401: \\[CWE-328\\] Use of weak cryptographic primitive"
	_ = h
}

func getUserInput() string {
	return "test"
}

func SecureFunction() {
	fmt.Println("This is secure")
}
