package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGosecutil(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gosecutil Suite")
}

var _ = Describe("newUtils", func() {
	It("should create utilities with all commands", func() {
		utils := newUtils()
		Expect(utils).NotTo(BeNil())
		Expect(utils.commands).To(HaveLen(7))
		Expect(utils.commands).To(HaveKey("ast"))
		Expect(utils.commands).To(HaveKey("callobj"))
		Expect(utils.commands).To(HaveKey("uses"))
		Expect(utils.commands).To(HaveKey("types"))
		Expect(utils.commands).To(HaveKey("defs"))
		Expect(utils.commands).To(HaveKey("comments"))
		Expect(utils.commands).To(HaveKey("imports"))
		Expect(utils.call).To(BeEmpty())
	})
})

var _ = Describe("utilities.String", func() {
	It("should return comma-separated list of commands", func() {
		utils := newUtils()
		str := utils.String()
		Expect(str).To(ContainSubstring("ast"))
		Expect(str).To(ContainSubstring("callobj"))
		Expect(str).To(ContainSubstring("uses"))
		Expect(str).To(ContainSubstring("types"))
		Expect(str).To(ContainSubstring("defs"))
		Expect(str).To(ContainSubstring("comments"))
		Expect(str).To(ContainSubstring("imports"))
	})

	It("should contain commas between commands", func() {
		utils := newUtils()
		str := utils.String()
		Expect(strings.Count(str, ",")).To(Equal(6)) // 7 commands = 6 commas
	})
})

var _ = Describe("utilities.Set", func() {
	var utils *utilities

	BeforeEach(func() {
		utils = newUtils()
	})

	It("should add valid command to call list", func() {
		err := utils.Set("ast")
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.call).To(HaveLen(1))
		Expect(utils.call[0]).To(Equal("ast"))
	})

	It("should add multiple commands", func() {
		err := utils.Set("ast")
		Expect(err).NotTo(HaveOccurred())
		err = utils.Set("types")
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.call).To(HaveLen(2))
		Expect(utils.call).To(ContainElement("ast"))
		Expect(utils.call).To(ContainElement("types"))
	})

	It("should return error for invalid command", func() {
		err := utils.Set("invalid")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("valid tools are"))
		Expect(utils.call).To(BeEmpty())
	})

	It("should accept all valid commands", func() {
		validCommands := []string{"ast", "callobj", "uses", "types", "defs", "comments", "imports"}
		for _, cmd := range validCommands {
			err := utils.Set(cmd)
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(utils.call).To(HaveLen(7))
	})
})

var _ = Describe("utilities.run", func() {
	var utils *utilities
	var tempFile *os.File

	BeforeEach(func() {
		utils = newUtils()
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main
func main() {}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should run selected command", func() {
		err := utils.Set("ast")
		Expect(err).NotTo(HaveOccurred())

		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		utils.run(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain AST output
		Expect(output).NotTo(BeEmpty())
	})

	It("should run multiple commands", func() {
		err := utils.Set("defs")
		Expect(err).NotTo(HaveOccurred())
		err = utils.Set("uses")
		Expect(err).NotTo(HaveOccurred())

		// Should not panic
		utils.run(tempFile.Name())
	})

	It("should handle no commands gracefully", func() {
		// Should not panic with empty call list
		utils.run(tempFile.Name())
	})
})

var _ = Describe("shouldSkip", func() {
	It("should return false for valid file", func() {
		tempFile, err := os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		result := shouldSkip(tempFile.Name())

		w.Close()
		os.Stderr = old
		_, _ = io.Copy(io.Discard, r)

		Expect(result).To(BeFalse())
	})

	It("should return true for non-existent file", func() {
		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		result := shouldSkip("/nonexistent/file.go")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(result).To(BeTrue())
		Expect(output).To(ContainSubstring("Skipping"))
	})

	It("should return true for directory", func() {
		tempDir, err := os.MkdirTemp("", "test-dir-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tempDir)

		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		result := shouldSkip(tempDir)

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(result).To(BeTrue())
		Expect(output).To(ContainSubstring("directory"))
	})
})

var _ = Describe("dumpAst", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump AST for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpAst(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// AST output should contain node information
		Expect(output).To(ContainSubstring("ast.File"))
	})

	It("should skip non-existent file", func() {
		// Capture stderr and stdout
		oldErr := os.Stderr
		oldOut := os.Stdout
		rErr, wErr, _ := os.Pipe()
		rOut, wOut, _ := os.Pipe()
		os.Stderr = wErr
		os.Stdout = wOut

		dumpAst("/nonexistent/file.go")

		wErr.Close()
		wOut.Close()
		os.Stderr = oldErr
		os.Stdout = oldOut

		var bufErr bytes.Buffer
		_, _ = io.Copy(&bufErr, rErr)
		_, _ = io.Copy(io.Discard, rOut)

		Expect(bufErr.String()).To(ContainSubstring("Skipping"))
	})

	It("should handle invalid Go file", func() {
		invalidFile, err := os.CreateTemp("", "invalid-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(invalidFile.Name())
		_, err = invalidFile.WriteString("invalid go code {{{")
		Expect(err).NotTo(HaveOccurred())
		invalidFile.Close()

		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		dumpAst(invalidFile.Name())

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(output).To(ContainSubstring("Unable to parse"))
	})

	It("should handle multiple files", func() {
		file2, err := os.CreateTemp("", "test2-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(file2.Name())
		_, err = file2.WriteString("package main\nfunc test() {}")
		Expect(err).NotTo(HaveOccurred())
		file2.Close()

		// Should not panic
		dumpAst(tempFile.Name(), file2.Name())
	})
})

var _ = Describe("createContext", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should create context for valid file", func() {
		ctx := createContext(tempFile.Name())
		Expect(ctx).NotTo(BeNil())
		Expect(ctx.fileset).NotTo(BeNil())
		Expect(ctx.info).NotTo(BeNil())
		Expect(ctx.pkg).NotTo(BeNil())
		Expect(ctx.config).NotTo(BeNil())
		Expect(ctx.root).NotTo(BeNil())
		// comments map may be empty for file without comments
	})

	It("should return nil for non-existent file", func() {
		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		ctx := createContext("/nonexistent/file.go")

		w.Close()
		os.Stderr = old
		_, _ = io.Copy(io.Discard, r)

		Expect(ctx).To(BeNil())
	})

	It("should return nil for invalid Go file", func() {
		invalidFile, err := os.CreateTemp("", "invalid-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(invalidFile.Name())
		_, err = invalidFile.WriteString("invalid go code {{{")
		Expect(err).NotTo(HaveOccurred())
		invalidFile.Close()

		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		ctx := createContext(invalidFile.Name())

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(ctx).To(BeNil())
		Expect(output).To(ContainSubstring("Unable to parse"))
	})

	It("should parse file with comments", func() {
		commentFile, err := os.CreateTemp("", "comment-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(commentFile.Name())
		_, err = commentFile.WriteString(`package main
// This is a comment
func main() {
	// Another comment
}
`)
		Expect(err).NotTo(HaveOccurred())
		commentFile.Close()

		ctx := createContext(commentFile.Name())
		Expect(ctx).NotTo(BeNil())
		Expect(ctx.comments).ToNot(BeEmpty())
	})
})

var _ = Describe("printObject", func() {
	It("should handle nil object", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		printObject(nil)

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(output).To(ContainSubstring("object is nil"))
	})

	It("should print object information", func() {
		tempFile, err := os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(`package main
func main() {}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()

		ctx := createContext(tempFile.Name())
		if ctx != nil && len(ctx.info.Defs) > 0 {
			for _, obj := range ctx.info.Defs {
				if obj != nil {
					// Capture stdout
					old := os.Stdout
					r, w, _ := os.Pipe()
					os.Stdout = w

					printObject(obj)

					w.Close()
					os.Stdout = old

					var buf bytes.Buffer
					_, _ = io.Copy(&buf, r)
					output := buf.String()

					Expect(output).To(ContainSubstring("OBJECT"))
					Expect(output).To(ContainSubstring("Name"))
					break
				}
			}
		}
	})
})

var _ = Describe("checkContext", func() {
	It("should return false for nil context", func() {
		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		result := checkContext(nil, "test.go")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(result).To(BeFalse())
		Expect(output).To(ContainSubstring("Failed to create context"))
	})

	It("should return true for valid context", func() {
		tempFile, err := os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(`package main
func main() {}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()

		ctx := createContext(tempFile.Name())
		result := checkContext(ctx, tempFile.Name())
		Expect(result).To(BeTrue())
	})
})

var _ = Describe("dumpCallObj", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump call objects for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpCallObj(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain object information
		Expect(output).To(ContainSubstring("OBJECT"))
	})

	It("should skip invalid files", func() {
		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		dumpCallObj("/nonexistent/file.go")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(output).To(ContainSubstring("Skipping"))
	})
})

var _ = Describe("dumpUses", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

import "fmt"

func main() {
	x := 5
	fmt.Println(x)
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump uses for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpUses(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain IDENT and OBJECT
		Expect(output).To(ContainSubstring("IDENT"))
	})

	It("should skip invalid files", func() {
		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		dumpUses("/nonexistent/file.go")

		w.Close()
		os.Stderr = old
		_, _ = io.Copy(io.Discard, r)

		// Should not panic
	})
})

var _ = Describe("dumpTypes", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

func main() {
	x := 5
	_ = x
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump types for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpTypes(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain EXPR and TYPE
		Expect(output).To(ContainSubstring("EXPR"))
		Expect(output).To(ContainSubstring("TYPE"))
	})

	It("should skip invalid files", func() {
		// Should not panic
		dumpTypes("/nonexistent/file.go")
	})
})

var _ = Describe("dumpDefs", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

func testFunc() {}

func main() {
	testFunc()
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump definitions for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpDefs(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain IDENT and OBJ
		Expect(output).To(ContainSubstring("IDENT"))
	})

	It("should skip invalid files", func() {
		// Should not panic
		dumpDefs("/nonexistent/file.go")
	})
})

var _ = Describe("dumpComments", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

// This is a comment
func main() {
	// Another comment
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump comments for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpComments(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain comment text
		Expect(output).To(ContainSubstring("This is a comment"))
	})

	It("should handle file with no comments", func() {
		noCommentFile, err := os.CreateTemp("", "nocomment-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(noCommentFile.Name())
		_, err = noCommentFile.WriteString("package main\nfunc main() {}")
		Expect(err).NotTo(HaveOccurred())
		noCommentFile.Close()

		// Should not panic
		dumpComments(noCommentFile.Name())
	})

	It("should skip invalid files", func() {
		// Should not panic
		dumpComments("/nonexistent/file.go")
	})
})

var _ = Describe("dumpImports", func() {
	var tempFile *os.File

	BeforeEach(func() {
		var err error
		tempFile, err = os.CreateTemp("", "test-*.go")
		Expect(err).NotTo(HaveOccurred())
		_, err = tempFile.WriteString(`package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("hello")
	os.Exit(0)
}
`)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()
	})

	AfterEach(func() {
		if tempFile != nil {
			os.Remove(tempFile.Name())
		}
	})

	It("should dump imports for valid file", func() {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		dumpImports(tempFile.Name())

		w.Close()
		os.Stdout = old

		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		// Should contain import information
		Expect(output).To(Or(ContainSubstring("fmt"), ContainSubstring("os")))
	})

	It("should handle file with no imports", func() {
		noImportFile, err := os.CreateTemp("", "noimport-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(noImportFile.Name())
		_, err = noImportFile.WriteString("package main\nfunc main() {}")
		Expect(err).NotTo(HaveOccurred())
		noImportFile.Close()

		// Should not panic
		dumpImports(noImportFile.Name())
	})

	It("should skip invalid files", func() {
		// Should not panic
		dumpImports("/nonexistent/file.go")
	})
})

var _ = Describe("Integration tests", func() {
	It("should handle complete workflow", func() {
		// Create test file
		tempFile, err := os.CreateTemp("", "workflow-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(tempFile.Name())

		testCode := `package main

import "fmt"

// HelloWorld prints hello
func HelloWorld() {
	fmt.Println("Hello, World!")
}

func main() {
	HelloWorld()
}
`
		_, err = tempFile.WriteString(testCode)
		Expect(err).NotTo(HaveOccurred())
		tempFile.Close()

		// Create utilities
		utils := newUtils()

		// Add all commands
		for _, cmd := range []string{"ast", "defs", "uses", "types", "comments", "imports", "callobj"} {
			err := utils.Set(cmd)
			Expect(err).NotTo(HaveOccurred())
		}

		// Run all commands - should not panic
		utils.run(tempFile.Name())
	})

	It("should handle multiple files in workflow", func() {
		// Create multiple test files
		files := make([]*os.File, 3)
		for i := 0; i < 3; i++ {
			var err error
			files[i], err = os.CreateTemp("", "multi-*.go")
			Expect(err).NotTo(HaveOccurred())
			defer os.Remove(files[i].Name())

			_, err = files[i].WriteString(`package main
func test` + string(rune('A'+i)) + `() {}
`)
			Expect(err).NotTo(HaveOccurred())
			files[i].Close()
		}

		// Test with dumpAst
		fileNames := []string{files[0].Name(), files[1].Name(), files[2].Name()}
		dumpAst(fileNames...)
	})

	It("should handle mixed valid and invalid files", func() {
		validFile, err := os.CreateTemp("", "valid-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(validFile.Name())
		_, err = validFile.WriteString("package main\nfunc main() {}")
		Expect(err).NotTo(HaveOccurred())
		validFile.Close()

		// Mix valid and invalid files
		dumpAst(validFile.Name(), "/nonexistent.go")
		// Should not panic
	})
})

var _ = Describe("Edge cases", func() {
	It("should handle empty file", func() {
		emptyFile, err := os.CreateTemp("", "empty-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(emptyFile.Name())
		emptyFile.Close()

		// Capture stderr
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		dumpAst(emptyFile.Name())

		w.Close()
		os.Stderr = old
		_, _ = io.Copy(io.Discard, r)

		// Should not panic
	})

	It("should handle file with only package declaration", func() {
		pkgFile, err := os.CreateTemp("", "pkg-*.go")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(pkgFile.Name())
		_, err = pkgFile.WriteString("package main")
		Expect(err).NotTo(HaveOccurred())
		pkgFile.Close()

		ctx := createContext(pkgFile.Name())
		Expect(ctx).NotTo(BeNil())
	})

	It("should handle very long file path", func() {
		// Create temporary directory with a reasonable path
		tempDir, err := os.MkdirTemp("", "test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tempDir)

		// Create file with long name
		longName := filepath.Join(tempDir, strings.Repeat("a", 100)+".go")
		err = os.WriteFile(longName, []byte("package main\nfunc main() {}"), 0600)
		if err == nil {
			defer os.Remove(longName)
			// Should not panic
			dumpAst(longName)
		}
	})
})
