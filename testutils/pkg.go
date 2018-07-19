package testutils

import (
	"fmt"
	"go/build"
	"go/parser"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/securego/gas"
	"golang.org/x/tools/go/loader"
)

type buildObj struct {
	pkg     *build.Package
	config  loader.Config
	program *loader.Program
}

// TestPackage is a mock package for testing purposes
type TestPackage struct {
	Path   string
	Files  map[string]string
	ondisk bool
	build  *buildObj
}

// NewTestPackage will create a new and empty package. Must call Close() to cleanup
// auxilary files
func NewTestPackage() *TestPackage {
	// Files must exist in $GOPATH
	sourceDir := path.Join(os.Getenv("GOPATH"), "src")
	workingDir, err := ioutil.TempDir(sourceDir, "gas_test")
	if err != nil {
		return nil
	}

	return &TestPackage{
		Path:   workingDir,
		Files:  make(map[string]string),
		ondisk: false,
		build:  nil,
	}
}

// AddFile inserts the filename and contents into the package contents
func (p *TestPackage) AddFile(filename, content string) {
	p.Files[path.Join(p.Path, filename)] = content
}

func (p *TestPackage) write() error {
	if p.ondisk {
		return nil
	}
	for filename, content := range p.Files {
		if e := ioutil.WriteFile(filename, []byte(content), 0644); e != nil {
			return e
		}
	}
	p.ondisk = true
	return nil
}

// Build ensures all files are persisted to disk and built
func (p *TestPackage) Build() error {
	if p.build != nil {
		return nil
	}
	if err := p.write(); err != nil {
		return err
	}
	basePackage, err := build.Default.ImportDir(p.Path, build.ImportComment)
	if err != nil {
		return err
	}

	var packageFiles []string
	packageConfig := loader.Config{Build: &build.Default, ParserMode: parser.ParseComments}
	for _, filename := range basePackage.GoFiles {
		packageFiles = append(packageFiles, path.Join(p.Path, filename))
	}

	packageConfig.CreateFromFilenames(basePackage.Name, packageFiles...)
	program, err := packageConfig.Load()
	if err != nil {
		return err
	}
	p.build = &buildObj{
		pkg:     basePackage,
		config:  packageConfig,
		program: program,
	}
	return nil
}

// CreateContext builds a context out of supplied package context
func (p *TestPackage) CreateContext(filename string) *gas.Context {
	if err := p.Build(); err != nil {
		log.Fatal(err)
		return nil
	}

	for _, pkg := range p.build.program.Created {
		for _, file := range pkg.Files {
			pkgFile := p.build.program.Fset.File(file.Pos()).Name()
			strip := fmt.Sprintf("%s%c", p.Path, os.PathSeparator)
			pkgFile = strings.TrimPrefix(pkgFile, strip)
			if pkgFile == filename {
				ctx := &gas.Context{
					FileSet: p.build.program.Fset,
					Root:    file,
					Config:  gas.NewConfig(),
					Info:    &pkg.Info,
					Pkg:     pkg.Pkg,
					Imports: gas.NewImportTracker(),
				}
				ctx.Imports.TrackPackages(ctx.Pkg.Imports()...)
				return ctx
			}
		}
	}
	return nil
}

// Close will delete the package and all files in that directory
func (p *TestPackage) Close() {
	if p.ondisk {
		err := os.RemoveAll(p.Path)
		if err != nil {
			log.Fatal(err)
		}
	}
}
