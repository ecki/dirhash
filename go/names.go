package main

import (
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

type pattern struct {
	boundaries [][]string
	directory  bool
}

func compilePattern(s string) (pattern, error) {
	p := pattern{}
	if !utf8.ValidString(s) || s == "" || strings.ContainsAny(s, "\\\x00") {
		return p, errors.New("malformed exclusion pattern")
	}
	p.directory = strings.HasSuffix(s, "/") && !strings.HasSuffix(s, "!/")
	if p.directory {
		s = strings.TrimSuffix(s, "/")
	}
	var segment strings.Builder
	var parts []string
	for i := 0; i < len(s); i++ {
		if s[i] != '!' {
			segment.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == '!' {
			segment.WriteByte('!')
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '/' {
			parts = append(parts, segment.String())
			segment.Reset()
			i++
			continue
		}
		return p, errors.New("literal exclamation marks in patterns require doubling")
	}
	parts = append(parts, segment.String())
	for _, part := range parts {
		cs := strings.Split(part, "/")
		for _, c := range cs {
			if c == "" || c == "." || c == ".." || strings.Contains(c, "**") && c != "**" {
				return p, errors.New("malformed exclusion path component")
			}
		}
		p.boundaries = append(p.boundaries, cs)
	}
	return p, nil
}
func componentMatch(p, s string) bool {
	// Greedy wildcard matching over scalars, with constant auxiliary storage.
	a, b := []rune(p), []rune(s)
	i, j, star, mark := 0, 0, -1, 0
	for j < len(b) {
		if i < len(a) && a[i] == b[j] {
			i++
			j++
		} else if i < len(a) && a[i] == '*' {
			star = i
			i++
			mark = j
		} else if star >= 0 {
			i = star + 1
			mark++
			j = mark
		} else {
			return false
		}
	}
	for i < len(a) && a[i] == '*' {
		i++
	}
	return i == len(a)
}
func pathMatch(p, s []string) bool {
	// Component-level ** cannot cross an archive boundary.
	dp := make([]bool, len(s)+1)
	dp[0] = true
	for _, c := range p {
		next := make([]bool, len(dp))
		if c == "**" {
			next[0] = dp[0]
			for j := 1; j < len(dp); j++ {
				next[j] = dp[j] || next[j-1]
			}
		} else {
			for j := 1; j < len(dp); j++ {
				next[j] = dp[j-1] && componentMatch(c, s[j-1])
			}
		}
		dp = next
	}
	return dp[len(s)]
}
func (o *options) excluded(chain []string, name string, isDir bool) bool {
	locations := append(append([]string{}, chain...), name)
	for _, p := range o.excludes {
		if len(p.boundaries) > len(locations) {
			continue
		}
		ok := true
		for i := 0; i < len(p.boundaries)-1; i++ {
			if !pathMatch(p.boundaries[i], strings.Split(locations[i], "/")) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		index := len(p.boundaries) - 1
		cs := strings.Split(locations[index], "/")
		for n := 1; n <= len(cs); n++ {
			dir := index < len(locations)-1 || n < len(cs) || isDir
			if (!p.directory || dir) && pathMatch(p.boundaries[index], cs[:n]) {
				return true
			}
		}
	}
	return false
}
func escaped(s string) string { return strings.ReplaceAll(s, "!", "!!") }
func display(source string, chain []string) string {
	s := escaped(source)
	for _, p := range chain {
		s += "!/" + escaped(p)
	}
	return s
}
func validPath(s string, directory bool) (string, error) {
	if !utf8.ValidString(s) {
		return "", fail("INVALID_ENCODING", "", "filename is not valid UTF-8")
	}
	if strings.ContainsAny(s, "\\\x00") || strings.HasPrefix(s, "/") {
		return "", fail("INVALID_PATH", "", "absolute, NUL or backslash path")
	}
	t := strings.TrimSuffix(s, "/")
	if strings.HasSuffix(s, "/") && !directory {
		return "", fail("INVALID_PATH", "", "non-directory with directory suffix")
	}
	if t == "" || s == "." {
		return "", fail("INVALID_PATH", "", "empty entry name")
	}
	cs := strings.Split(t, "/")
	for len(cs) > 0 && cs[0] == "." {
		cs = cs[1:]
	}
	if len(cs) > 0 && len(cs[0]) >= 2 && ((cs[0][0] >= 'A' && cs[0][0] <= 'Z') || (cs[0][0] >= 'a' && cs[0][0] <= 'z')) && cs[0][1] == ':' {
		return "", fail("INVALID_PATH", "", "drive-qualified path")
	}
	for _, c := range cs {
		if c == "" || c == "." || c == ".." {
			return "", fail("INVALID_PATH", "", "empty or dot path component")
		}
	}
	if len(cs) == 0 && !directory {
		return "", fail("INVALID_PATH", "", "root marker must be a directory")
	}
	return strings.Join(cs, "/"), nil
}
func portableComponent(s string) error {
	for _, r := range s {
		if unicode16Control(r) || r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFF == 0xFFFE || r&0xFFFF == 0xFFFF || strings.ContainsRune(`<>:"|?*`, r) {
			return fail("INVALID_PATH", "", "nonportable character in name")
		}
	}
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return fail("INVALID_PATH", "", "name ends in dot or space")
	}
	base := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
	if contains([]string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}, base) {
		return fail("INVALID_PATH", "", "reserved device name")
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		rest := base[3:]
		if contains([]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"}, rest) {
			return fail("INVALID_PATH", "", "reserved device name")
		}
	}
	return nil
}
func strictPath(s string) error {
	for _, c := range strings.Split(s, "/") {
		if c != "" {
			if e := portableComponent(c); e != nil {
				return e
			}
		}
	}
	return nil
}
func at(err error, location string) error {
	if f, ok := err.(*failure); ok && f.location == "" {
		g := *f
		g.location = location
		return &g
	}
	return err
}
func projected(stored string, directory bool, n uint64) (string, string, error) {
	suffix := strings.HasSuffix(stored, "/")
	cs := strings.Split(strings.TrimSuffix(stored, "/"), "/")
	if n >= uint64(len(cs)) {
		if !directory {
			return "", "", fail("INVALID_PATH", "", "prefix stripping consumes a non-directory entry")
		}
		return "", "", nil
	}
	v := strings.Join(cs[int(n):], "/")
	if suffix {
		v += "/"
	}
	p, e := validPath(v, directory)
	return p, v, e
}

func resolveLink(entries map[string]*entry, start string) (string, error) {
	e := entries[start]
	if e == nil {
		return "", fail("DANGLING_SYMLINK", "", "target does not exist")
	}
	parts := []string{}
	if p := path.Dir(start); p != "." {
		parts = strings.Split(p, "/")
	}
	t := string(e.target)
	if e.kind != 'l' {
		return start, nil
	}
	if err := validTarget(t); err != nil {
		return "", err
	}
	queue := strings.Split(t, "/")
	visited := map[string]bool{start: true}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if strings.HasPrefix(c, "\x00") {
			delete(visited, c[1:])
			continue
		}
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			if len(parts) == 0 {
				return "", fail("UNSAFE_SYMLINK", "", "target escapes archive root")
			}
			parts = parts[:len(parts)-1]
			continue
		}
		parts = append(parts, c)
		p := strings.Join(parts, "/")
		node := entries[p]
		if node == nil {
			return "", fail("DANGLING_SYMLINK", "", "target does not exist")
		}
		if node.kind == 'l' {
			if visited[p] {
				return "", fail("UNSAFE_SYMLINK", "", "cyclic symlink chain")
			}
			visited[p] = true
			v := string(node.target)
			if err := validTarget(v); err != nil {
				return "", err
			}
			parts = parts[:len(parts)-1]
			expanded := append(strings.Split(v, "/"), "\x00"+p)
			queue = append(expanded, queue...)
		} else if node.kind != 'd' {
			for _, next := range queue {
				if !strings.HasPrefix(next, "\x00") {
					return "", fail("DANGLING_SYMLINK", "", "non-directory target component")
				}
			}
		}
	}
	return strings.Join(parts, "/"), nil
}
func validTarget(t string) error {
	if !utf8.ValidString(t) {
		return fail("INVALID_ENCODING", "", "symlink target is not UTF-8")
	}
	if t == "" || strings.ContainsAny(t, "\\\x00") || strings.HasPrefix(t, "/") || len(t) >= 2 && t[1] == ':' {
		return fail("UNSAFE_SYMLINK", "", "invalid or absolute target")
	}
	return nil
}
