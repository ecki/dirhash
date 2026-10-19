// Command packaging collects notices from the packages actually linked for each release target.
package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir string
	Main               bool
}

type pkg struct {
	Dir    string
	Module *module
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run ./packaging OUTPUT_DIRECTORY")
	}
	if err := collect(os.Args[1]); err != nil {
		panic(err)
	}
}

func collect(out string) error {
	dest := filepath.Join(out, "THIRD-PARTY-LICENSES")
	goRoot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return err
	}
	root := strings.TrimSpace(string(goRoot))
	modules := map[string]bool{}
	copied := map[string]bool{}
	for _, target := range []struct{ os, arch, binary string }{
		{"linux", "amd64", "dirhash-linux-amd64"},
		{"linux", "arm64", "dirhash-linux-arm64"},
		{"windows", "amd64", "dirhash-windows-amd64.exe"},
	} {
		info, err := buildinfo.ReadFile(filepath.Join(out, target.binary))
		if err != nil {
			return err
		}
		linked := map[string]bool{}
		for _, dep := range info.Deps {
			if dep.Replace != nil {
				return fmt.Errorf("license review required for replaced module %s", dep.Path)
			}
			linked[dep.Path+"@"+dep.Version] = false
		}
		cmd := exec.Command("go", "list", "-deps", "-json", ".")
		cmd.Env = append(os.Environ(), "GOOS="+target.os, "GOARCH="+target.arch, "CGO_ENABLED=0")
		data, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("list %s/%s packages: %w", target.os, target.arch, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var p pkg
			if err := decoder.Decode(&p); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			if p.Module == nil {
				if p.Dir != "" {
					if err := copyAncestors(p.Dir, root, filepath.Join(dest, "Go-"+runtime.Version()), copied); err != nil {
						return err
					}
				}
				continue
			}
			if p.Module.Main {
				continue
			}
			key := p.Module.Path + "@" + p.Module.Version
			if _, ok := linked[key]; !ok {
				return fmt.Errorf("listed module %s absent from %s build metadata", key, target.binary)
			}
			linked[key] = true
			modules[key] = true
			if err := copyAncestors(p.Dir, p.Module.Dir, filepath.Join(dest, filepath.FromSlash(key)), copied); err != nil {
				return err
			}
			if !copied[filepath.Join(p.Module.Dir, "LICENSE")] {
				return fmt.Errorf("module %s has no root LICENSE; review required", key)
			}
		}
		for key, found := range linked {
			if !found {
				return fmt.Errorf("linked module %s has no license input", key)
			}
		}
	}
	for _, name := range []string{"LICENSE", "PATENTS"} {
		if err := copyLegal(filepath.Join(root, name), filepath.Join(dest, "Go-"+runtime.Version(), name)); err != nil {
			return err
		}
	}
	if err := copyLegal("UNICODE-LICENSE.txt", filepath.Join(dest, "Unicode-16.0.0", "LICENSE")); err != nil {
		return err
	}
	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	index := "Runtime dependency licenses and notices (original bytes).\n" +
		"Redistribute this directory with each Go executable, together with LICENSE and NOTICE.\n" +
		"Includes the Go runtime/standard library and generated Unicode 16.0.0 data.\n\n" +
		strings.Join(keys, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dest, "INDEX.txt"), []byte(index), 0o644); err != nil {
		return err
	}
	fmt.Printf("Verified and copied notices for %d linked modules, Go and Unicode.\n", len(modules))
	return nil
}

func copyAncestors(dir, root, dest string, copied map[string]bool) error {
	for {
		rel, err := filepath.Rel(root, dir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("package directory outside source root: %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !legal(entry.Name()) {
				continue
			}
			source := filepath.Join(dir, entry.Name())
			if copied[source] {
				continue
			}
			if err := copyLegal(source, filepath.Join(dest, rel, entry.Name())); err != nil {
				return err
			}
			copied[source] = true
		}
		if dir == root {
			return nil
		}
		dir = filepath.Dir(dir)
	}
}

func legal(name string) bool {
	name = strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "NOTICE", "COPYING", "COPYRIGHT", "PATENTS"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func copyLegal(source, dest string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("empty legal file: %s", source)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return err
	}
	actual, err := os.ReadFile(dest)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, actual) {
		return fmt.Errorf("legal file changed while copying: %s", source)
	}
	return nil
}
