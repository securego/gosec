package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG204 - Subprocess auditing
var SampleCodeG204 = []CodeSample{
	{[]string{`
package main

import (
	"log"
	"os/exec"
	"context"
)

func main() {
	err := exec.CommandContext(context.Background(), "git", "rev-parse", "--show-toplevel").Run()
 	if err != nil {
		log.Fatal(err)
	}
  	log.Printf("Command finished with error: %v", err)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// Calling any function which starts a new process with using
// command line arguments as it's arguments is considered dangerous
package main

import (
	"context"
	"log"
	"os"
	"os/exec"
)

func main() {
	err := exec.CommandContext(context.Background(), os.Args[0], "5").Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Command finished with error: %v", err)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// Initializing a local variable using a environmental
// variable is consider as a dangerous user input
package main

import (
	"log"
	"os"
	"os/exec"
)

func main() {
	run := "sleep" + os.Getenv("SOMETHING")
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// gosec doesn't have enough context to decide that the
// command argument of the RunCmd function is hardcoded string
// and that's why it's better to warn the user so he can audit it
package main

import (
	"log"
	"os/exec"
)

func RunCmd(command string) {
	cmd := exec.Command(command, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
}

func main() {
	RunCmd("sleep")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log"
	"os/exec"
)

func RunCmd(a string, c string) {
	cmd := exec.Command(c)
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()

	cmd = exec.Command(a)
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
}

func main() {
	RunCmd("ll", "ls")
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// syscall.Exec function called with hardcoded arguments
// shouldn't be consider as a command injection
package main

import (
	"fmt"
	"syscall"
)

func main() {
	err := syscall.Exec("/bin/cat", []string{"/etc/passwd"}, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
`}, 0, gosec.NewConfig()},
	{
		[]string{`
package main

import (
	"fmt"
	"syscall"
)

func RunCmd(command string) {
	_, err := syscall.ForkExec(command, []string{}, nil)
	if err != nil {
	    fmt.Printf("Error: %v\n", err)
	}
}

func main() {
	RunCmd("sleep")
}
`}, 1, gosec.NewConfig(),
	},
	{[]string{`
package main

import (
	"fmt"
	"syscall"
)

func RunCmd(command string) {
	_, _, err := syscall.StartProcess(command, []string{}, nil)
	if err != nil {
	    fmt.Printf("Error: %v\n", err)
	}
}

func main() {
	RunCmd("sleep")
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// starting a process with a variable as an argument
// even if not constant is not considered as dangerous
// because it has hardcoded value
package main

import (
	"log"
	"os/exec"
)

func main() {
	run := "sleep"
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
// exec.Command from supplemental package sys/execabs
// using variable arguments
package main

import (
	"context"
	"log"
	"os"
	exec "golang.org/x/sys/execabs"
)

func main() {
	err := exec.CommandContext(context.Background(), os.Args[0], "5").Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Command finished with error: %v", err)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
// Initializing a local variable using a environmental
// variable is consider as a dangerous user input
package main

import (
	"log"
	"os"
	"os/exec"
)

func main() {
	var run = "sleep" + os.Getenv("SOMETHING")
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}
`}, 1, gosec.NewConfig()},
}
