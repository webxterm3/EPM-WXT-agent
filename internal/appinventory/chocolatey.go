package appinventory

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// SourceChocolatey marks a package Chocolatey installed.
const SourceChocolatey = "chocolatey"

// DefaultChocolateyRoot is where Chocolatey installs unless it was told
// otherwise, in which case the ChocolateyInstall environment variable says so.
const DefaultChocolateyRoot = `C:\ProgramData\chocolatey`

// ChocolateyCollector reads Chocolatey's package library.
//
// Most Chocolatey packages wrap an ordinary installer and therefore also
// appear in the uninstall registry, where the registry collector finds them.
// The ones that do not are exactly the interesting ones: portable packages and
// command-line tools, installed with no installer, no uninstall entry and no
// Add/Remove Programs row. On a developer's machine that is most of what is
// there, and to every other collector it is invisible.
//
// Like the Homebrew collector this reads the filesystem rather than running
// the tool. `choco list` is slow, writes to its own log, and on some versions
// prompts; the package library is a directory of XML.
type ChocolateyCollector struct {
	// Root is the Chocolatey install directory. Empty means the
	// ChocolateyInstall environment variable, then DefaultChocolateyRoot.
	Root string
}

func (c *ChocolateyCollector) Name() string { return "chocolatey" }

func (c *ChocolateyCollector) root() string {
	if c.Root != "" {
		return c.Root
	}
	if env := os.Getenv("ChocolateyInstall"); env != "" {
		return env
	}
	return DefaultChocolateyRoot
}

// Collect reads <root>\lib, one directory per installed package.
func (c *ChocolateyCollector) Collect(ctx context.Context) ([]Application, error) {
	root := c.root()
	lib := filepath.Join(root, "lib")

	entries, err := os.ReadDir(lib)
	if err != nil {
		// No Chocolatey on this machine is the normal case, not a failure.
		return nil, nil
	}

	var apps []Application
	for _, entry := range entries {
		if ctx.Err() != nil {
			return apps, ctx.Err()
		}
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		spec, ok := readNuspec(filepath.Join(lib, entry.Name()))
		if !ok {
			continue
		}
		app := applicationFromNuspec(spec, entry.Name(), filepath.Join(lib, entry.Name()))
		app.ExePath = chocolateyShim(root, spec, entry.Name())
		apps = append(apps, app)
	}
	return apps, nil
}

// nuspec is the part of a NuGet package manifest worth reading.
type nuspec struct {
	ID          string `xml:"metadata>id"`
	Version     string `xml:"metadata>version"`
	Title       string `xml:"metadata>title"`
	Authors     string `xml:"metadata>authors"`
	Owners      string `xml:"metadata>owners"`
	Description string `xml:"metadata>description"`
}

// readNuspec finds and parses the manifest in a package directory.
func readNuspec(dir string) (nuspec, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nuspec{}, false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".nuspec") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a path derived from a directory listing the agent walked
		if err != nil {
			continue
		}
		var spec nuspec
		if err := xml.Unmarshal(data, &spec); err != nil {
			continue
		}
		return spec, true
	}
	return nuspec{}, false
}

// applicationFromNuspec turns a manifest into an inventory record.
func applicationFromNuspec(spec nuspec, dirName, installPath string) Application {
	id := strings.TrimSpace(spec.ID)
	if id == "" {
		id = dirName
	}

	// Title is the human name ("Google Chrome"); id is the package name
	// ("googlechrome"). An operator writing policy recognises the first and
	// searches the catalogue for it, so it wins where it exists.
	name := strings.TrimSpace(spec.Title)
	if name == "" {
		name = id
	}

	// Authors is the software's publisher; owners is whoever maintains the
	// Chocolatey package, which is frequently a community volunteer and not
	// the vendor a publisher rule means.
	publisher := strings.TrimSpace(spec.Authors)
	if publisher == "" {
		publisher = strings.TrimSpace(spec.Owners)
	}

	return Application{
		ID:          "chocolatey:" + strings.ToLower(id),
		Name:        name,
		Version:     strings.TrimSpace(spec.Version),
		Publisher:   publisher,
		InstallPath: installPath,
		Scope:       ScopeMachine,
		Source:      SourceChocolatey,
	}
}

// chocolateyShim is the executable a package puts on the PATH.
//
// Chocolatey generates a shim in <root>\bin for each command a package
// provides, and that shim is what actually runs — so it is what enforcement
// has to act on. The package id is the usual name; the manifest title is
// tried as well for packages whose command is named after the product.
func chocolateyShim(root string, spec nuspec, dirName string) string {
	bin := filepath.Join(root, "bin")
	for _, candidate := range []string{strings.TrimSpace(spec.ID), dirName} {
		if candidate == "" {
			continue
		}
		path := filepath.Join(bin, candidate+".exe")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
