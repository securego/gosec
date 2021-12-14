package testutils

import (
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/securego/gosec/v2"
	"golang.org/x/tools/go/packages"
)

type buildObj struct {
	pkg    *build.Package
	config *packages.Config
	pkgs   []*packages.Package
}

// TestPackage is a mock package for testing purposes
type TestPackage struct {
	Path   string
	Files  map[string]string
	onDisk bool
	build  *buildObj
}

// NewTestPackage will create a new and empty package. Must call Close() to cleanup
// auxiliary files
func NewTestPackage() *TestPackage {
	workingDir, err := ioutil.TempDir("", "gosecs_test")
	if err != nil {
		return nil
	}

	return &TestPackage{
		Path:   workingDir,
		Files:  make(map[string]string),
		onDisk: false,
		build:  nil,
	}
}

// AddFile inserts the filename and contents into the package contents
func (p *TestPackage) AddFile(filename, content string) {
	p.Files[path.Join(p.Path, filename)] = content
}

func (p *TestPackage) write() error {
	if p.onDisk {
		return nil
	}
	for filename, content := range p.Files {
		if e := ioutil.WriteFile(filename, []byte(content), 0o644); e != nil {
			return e
		} //#nosec G306
	}
	p.onDisk = true
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
	for _, filename := range basePackage.GoFiles {
		packageFiles = append(packageFiles, path.Join(p.Path, filename))
	}

	conf := &packages.Config{
		Mode:  gosec.LoadMode,
		Tests: false,
	}
	pkgs, err := packages.Load(conf, packageFiles...)
	if err != nil {
		return err
	}
	p.build = &buildObj{
		pkg:    basePackage,
		config: conf,
		pkgs:   pkgs,
	}
	return nil
}

// CreateContext builds a context out of supplied package context
func (p *TestPackage) CreateContext(filename string) *gosec.Context {
	if err := p.Build(); err != nil {
		log.Fatal(err)
		return nil
	}

	for _, pkg := range p.build.pkgs {
		for _, file := range pkg.Syntax {
			pkgFile := pkg.Fset.File(file.Pos()).Name()
			strip := fmt.Sprintf("%s%c", p.Path, os.PathSeparator)
			pkgFile = strings.TrimPrefix(pkgFile, strip)
			if pkgFile == filename {
				ctx := &gosec.Context{
					FileSet:      pkg.Fset,
					Root:         file,
					Config:       gosec.NewConfig(),
					Info:         pkg.TypesInfo,
					Pkg:          pkg.Types,
					Imports:      gosec.NewImportTracker(),
					PassedValues: make(map[string]interface{}),
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
	if p.onDisk {
		err := os.RemoveAll(p.Path)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Pkgs returns the current built packages
func (p *TestPackage) Pkgs() []*packages.Package {
	if p.build != nil {
		return p.build.pkgs
	}
	return []*packages.Package{}
}

// PrintErrors prints to os.Stderr the accumulated errors of built packages
func (p *TestPackage) PrintErrors() int {
	return packages.PrintErrors(p.Pkgs())
}
