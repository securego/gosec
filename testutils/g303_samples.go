package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG303 - bad tempfile permissions & hardcoded shared path
var SampleCodeG303 = []CodeSample{
	{[]string{`
package samples

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
)

func main() {
	err := ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	f, err := os.Create("/tmp/demo2")
	if err != nil {
		fmt.Println("Error while writing!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	err = os.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile("/usr/tmp/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile("/tmp/" + "demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(os.TempDir() + "/demo2", []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(path.Join("/var/tmp", "demo2"), []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(path.Join(os.TempDir(), "demo2"), []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(filepath.Join(os.TempDir(), "demo2"), []byte("This is some data"), 0644)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
`}, 9, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	demoPath = "/tmp/demo2"
	tmpDir   = "/var/tmp"
)

func main() {
	f, err := os.Create(demoPath)
	if err != nil {
		fmt.Println("Error while writing!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	err = os.WriteFile(tmpDir+"/demo2", []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(filepath.Join(tmpDir, "demo2"), []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
`}, 3, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
)

func main() {
	err := os.WriteFile(sharedPath, []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
`, `
package samples

const sharedPath = "/tmp/demo2"
`}, 1, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	dataDir  = "/var/lib/demo"
	dataFile = dataDir + "/demo2"
)

func main() {
	err := os.WriteFile(dataFile, []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(filepath.Join(dataDir, "demo2"), []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
	"path/filepath"
)

const createFlags = os.O_RDWR | os.O_CREATE | os.O_TRUNC

func main() {
	f, err := os.OpenFile("/tmp/demo2", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	f, err = os.OpenFile(filepath.Join(os.TempDir(), "demo2"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	f, err = os.OpenFile("/var/tmp/demo2", createFlags, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
}
`}, 3, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
)

func open(name string, flag int) {
	f, err := os.OpenFile(name, flag, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
}

func main() {
	f, err := os.OpenFile("/tmp/demo2", os.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	f, err = os.OpenFile("/tmp/demo2", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	f, err = os.OpenFile("/var/lib/demo/demo2", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	open("/tmp/demo2", os.O_RDONLY)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const tmpDir = "tmp"

func write(name string) {
	err := os.WriteFile(path.Join("/var", "tmp", name), []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	f, err := os.OpenFile(filepath.Join("/", tmpDir, name), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error while opening!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
}

func main() {
	f, err := os.Create(filepath.Join("/", "tmp", "demo2"))
	if err != nil {
		fmt.Println("Error while writing!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	write("demo2")
}
`}, 3, gosec.NewConfig()},
	{[]string{`
package samples

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

func write(name string) {
	err := os.WriteFile(filepath.Join("/", "tmpdata", name), []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
	err = os.WriteFile(path.Join("/var", name, "tmp"), []byte("This is some data"), 0600)
	if err != nil {
		fmt.Println("Error while writing!")
	}
}

func main() {
	f, err := os.Create(filepath.Join("/", "var", "lib", "demo2"))
	if err != nil {
		fmt.Println("Error while writing!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	f, err = os.Create(filepath.Join())
	if err != nil {
		fmt.Println("Error while writing!")
	} else if err = f.Close(); err != nil {
		fmt.Println("Error while closing!")
	}
	write("demo2")
}
`}, 0, gosec.NewConfig()},
}
