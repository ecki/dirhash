package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type opener func() (io.ReadCloser, error)
type entry struct {
	name, original, stored string
	kind                   byte
	mode                   uint32
	size                   int64
	explicit, included     bool
	target                 []byte
	hardlink               string
	archiveHint            string
	discoveryError         error
	raw, blob, goRaw       map[string][]byte
	open                   opener
	seekOnly               bool
	typeKnown              bool
	linkExtra              []byte
	aliasDiscovered        bool
}
type namespace struct {
	engine            *engine
	chain             []string
	inputType         string
	entries, original map[string]*entry
	manifest          []*entry
	children          []*namespace
	opener            opener
	depth             uint64
	top               bool
	byteLength        int64
	zipMetadata       map[string]*zip.File
	zipLocalExtras    map[string][]byte
	seekable          bool
}

func (e *engine) diagnosticLocation(chain []string) string {
	if !e.filesystemInput {
		return display(e.o.source, chain)
	}
	if len(chain) == 0 {
		return e.o.source
	}
	source := filepath.Join(e.o.source, filepath.FromSlash(chain[0]))
	if len(chain) == 1 {
		return source
	}
	return display(source, chain[1:])
}

func (e *engine) resultPath(chain []string) string {
	if len(chain) == 0 {
		return e.o.source
	}
	if e.filesystemInput {
		prefix := filepath.Join(e.o.source, filepath.FromSlash(chain[0]))
		if len(chain) == 1 {
			return prefix
		}
		result := escaped(prefix)
		for _, archive := range chain[1:] {
			result += "!/" + escaped(archive)
		}
		return result
	}
	result := escaped(e.o.source)
	for _, archive := range chain {
		result += "!/" + escaped(archive)
	}
	return result
}

func (n *namespace) location() string { return n.engine.diagnosticLocation(n.chain) }
func (n *namespace) entryLocation(p string) string {
	return n.engine.diagnosticLocation(append(append([]string{}, n.chain...), p))
}
func (n *namespace) checkName(s string) error {
	if n.engine.h1 && strings.Contains(s, "\n") {
		return fail("INVALID_PATH", n.location(), "LF in h1 filename")
	}
	if n.engine.o.strict {
		return at(strictPath(s), n.location())
	}
	return nil
}
func (n *namespace) insert(m map[string]*entry, p string, e *entry, charge bool) error {
	if p == "" {
		if m[""].explicit {
			return fail("DUPLICATE_ENTRY", n.location(), "duplicate root directory marker")
		}
		m[""].explicit = true
		return nil
	}
	cs := strings.Split(p, "/")
	for i := 1; i < len(cs); i++ {
		parent := strings.Join(cs[:i], "/")
		originalParent := parent
		if !charge {
			originalParts := strings.Split(e.original, "/")
			difference := len(originalParts) - len(cs)
			if difference+i > 0 && difference+i <= len(originalParts) {
				originalParent = strings.Join(originalParts[:difference+i], "/")
			}
		}
		parentIncluded := !n.engine.o.excluded(n.chain, originalParent, true)
		if old := m[parent]; old != nil {
			if old.kind != 'd' {
				return fail("DUPLICATE_ENTRY", n.location(), "entry below non-directory")
			}
			if !charge && !old.explicit {
				old.included = old.included || parentIncluded
			}
		} else {
			if charge {
				if err := n.engine.chargeEntries(1, n.location()); err != nil {
					return err
				}
			}
			m[parent] = &entry{name: parent, original: originalParent, kind: 'd', included: parentIncluded}
		}
	}
	if old := m[p]; old != nil {
		if old.kind != 'd' || e.kind != 'd' || old.explicit {
			return fail("DUPLICATE_ENTRY", n.location(), "duplicate or conflicting entry "+quote(p))
		}
		// An implicit directory is charged when inferred, not again here.
	} else if charge {
		if err := n.engine.chargeEntries(1, n.location()); err != nil {
			return err
		}
	}
	m[p] = e
	return nil
}
func (n *namespace) add(stored string, kind byte, mode uint32, size int64, open opener) (*entry, error) {
	logical, repeatedSlash := stored, false
	// Non-strict compatibility (e.g. JDK ct.sym): an empty ZIP directory marker
	// with repeated trailing slashes is read as its single-slash form.
	if n.inputType == "zip" && !n.engine.o.strict && kind == 'd' && size == 0 && strings.HasSuffix(stored, "//") {
		if trimmed := strings.TrimRight(stored, "/") + "/"; trimmed != "/" {
			if _, err := validPath(trimmed, true); err == nil {
				logical, repeatedSlash = trimmed, true
			}
		}
	}
	p, err := validPath(logical, kind == 'd')
	if err != nil {
		return nil, at(err, n.entryLocation(stored))
	}
	if err = n.checkName(p); err != nil {
		if failure, ok := err.(*failure); ok {
			copy := *failure
			copy.location = n.entryLocation(stored)
			return nil, &copy
		}
		return nil, err
	}
	e := &entry{name: p, original: p, stored: stored, kind: kind, mode: mode, size: size, explicit: true, included: !n.engine.o.excluded(n.chain, p, kind == 'd'), open: open}
	if err = n.insert(n.original, p, e, true); err != nil {
		return nil, err
	}
	name, manifest := p, stored
	if n.top && n.inputType != "directory" && n.engine.o.strip > 0 {
		name, manifest, err = projected(logical, kind == 'd', n.engine.o.strip)
		if err != nil {
			return nil, at(err, n.location())
		}
	}
	e.name = name
	e.stored = manifest
	if n.original != nil && n.entries != nil && (name != "" || manifest != "") {
		if err = n.insert(n.entries, name, e, false); err != nil {
			return nil, err
		}
	}
	if manifest != "" {
		if repeatedSlash {
			manifest += stored[len(logical):]
			e.stored = manifest
		}
		n.manifest = append(n.manifest, e)
	}
	if repeatedSlash {
		n.engine.addWarning("WARN_ZIP_DIRECTORY_SLASH", n.entryLocation(stored), "accepted empty ZIP directory with repeated trailing slashes")
	}
	return e, nil
}
func (n *namespace) validate() error {
	// Resolve hard links against the complete original namespace.
	for _, e := range n.original {
		if e.kind != 'h' {
			continue
		}
		p := e.hardlink
		visited := map[string]bool{e.original: true}
		for {
			if visited[p] {
				return fail("INVALID_HARDLINK", n.location(), "cyclic hard link")
			}
			visited[p] = true
			t := n.original[p]
			if t == nil {
				return fail("INVALID_HARDLINK", n.location(), "missing hard-link target")
			}
			if t.kind == 'h' {
				p = t.hardlink
				continue
			}
			if t.kind != 'f' {
				return fail("INVALID_HARDLINK", n.location(), "hard-link target is not regular")
			}
			e.kind = 'f'
			e.size = t.size
			e.raw = t.raw
			e.blob = t.blob
			e.goRaw = t.goRaw
			e.open = t.open
			e.seekOnly = t.seekOnly
			e.archiveHint = t.archiveHint
			if err := n.engine.chargeExpanded(uint64(e.size), n.location()); err != nil {
				return err
			}
			if !e.aliasDiscovered && e.included && (n.engine.o.strict || n.engine.o.recurse) && (e.archiveHint != "" || suffixType(e.original) != "") {
				if !e.seekOnly && !n.engine.onlyNAR() {
					return fail("UNSUPPORTED_STREAMING", n.entryLocation(e.original), "TAR archive hard-link discovery requires unavailable seek-only target access")
				}
				r, err := e.open()
				if err != nil {
					return err
				}
				err = n.engine.payload(n, e, r, false, true)
				closeErr := r.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
			}
			break
		}
	}
	if n.engine.o.strict {
		for _, m := range []map[string]*entry{n.original, n.entries} {
			collisions := map[string]string{}
			for p, e := range m {
				if p == "" {
					continue
				}
				key := path.Dir(p) + "/" + unicode16Fold(path.Base(p))
				if old, ok := collisions[key]; ok && old != p {
					return fail("NAME_COLLISION", n.location(), "Unicode sibling collision")
				}
				collisions[key] = p
				if e.kind == 'l' && n.inputType != "directory" {
					if _, err := resolveLink(m, p); err != nil {
						return at(err, n.entryLocation(e.original))
					}
				}
			}
		}
	}
	return nil
}
func (n *namespace) hashes() ([]record, error) {
	o := n.engine.o
	nar := map[string][]byte{}
	plain := map[string][]byte{}
	var narWriters []io.Writer
	var narHashes []hash.Hash
	var narAlgs []string
	var plainWriters []io.Writer
	var plainHashes []hash.Hash
	var plainAlgs []string
	for _, s := range o.selected {
		switch s.scheme {
		case "nar":
			h := digest(s.algorithm)
			narHashes = append(narHashes, h)
			narWriters = append(narWriters, h)
			narAlgs = append(narAlgs, s.algorithm)
		case "plain":
			h := digest(s.algorithm)
			plainHashes = append(plainHashes, h)
			plainWriters = append(plainWriters, h)
			plainAlgs = append(plainAlgs, s.algorithm)
		}
	}
	if len(narWriters) > 0 {
		if err := n.writeNAR(io.MultiWriter(narWriters...)); err != nil {
			return nil, err
		}
		for i, h := range narHashes {
			nar[narAlgs[i]] = h.Sum(nil)
		}
	}
	if len(plainWriters) > 0 {
		if err := n.hashPlain(plainWriters); err != nil {
			return nil, err
		}
		for i, h := range plainHashes {
			plain[plainAlgs[i]] = h.Sum(nil)
		}
	}
	records := make([]record, 0, len(o.selected))
	for _, s := range o.selected {
		var result []byte
		var err error
		switch s.scheme {
		case "h1", "h1-go":
			h := digest(s.algorithm)
			list := make([]*entry, 0, len(n.entries))
			if s.scheme == "h1-go" {
				for _, e := range n.manifest {
					if e.included && (n.inputType != "directory" || e.kind != 'd') {
						list = append(list, e)
					}
				}
			} else {
				for p, e := range n.entries {
					if p != "" && e.included && e.kind != 'd' {
						list = append(list, e)
					}
				}
			}
			sort.Slice(list, func(i, j int) bool {
				if s.scheme == "h1-go" {
					return list[i].stored < list[j].stored
				}
				return list[i].name < list[j].name
			})
			for _, e := range list {
				p := e.name
				v := e.raw[s.algorithm]
				if s.scheme == "h1-go" {
					p = e.stored
					v = e.goRaw[s.algorithm]
					if v == nil {
						v = e.raw[s.algorithm]
					}
				}
				if e.kind == 'd' {
					v = sum(s.algorithm, nil)
				}
				_, _ = fmt.Fprintf(h, "%s  %s\n", hex.EncodeToString(v), p)
			}
			result = h.Sum(nil)
		case "gittree", "swhid":
			result, err = n.git(s)
		case "nar":
			result = nar[s.algorithm]
		case "plain":
			result = plain[s.algorithm]
		}
		if err != nil {
			return nil, err
		}
		chain := append([]string{}, n.chain...)
		if chain == nil {
			chain = []string{}
		}
		records = append(records, record{n.engine.resultPath(n.chain), o.source, chain, n.inputType, s.scheme, s.algorithm, render(s, result)})
	}
	return records, nil
}

func (n *namespace) hashPlain(writers []io.Writer) error {
	if n.opener == nil {
		return fail("UNSUPPORTED_FORMAT", n.location(), "plain digests require an archive input")
	}
	r, err := n.opener()
	if err != nil {
		return err
	}
	var source io.Reader = r
	if n.engine.o.ctx != nil {
		source = &contextReader{r: r, ctx: n.engine.o.ctx, location: n.location()}
	}
	counter := &countWriter{}
	writers = append(writers, counter)
	_, copyErr := io.CopyBuffer(io.MultiWriter(writers...), source, make([]byte, 32768))
	closeErr := r.Close()
	if copyErr != nil {
		var f *failure
		if errors.As(copyErr, &f) {
			return copyErr
		}
		return fail("ARCHIVE_INTEGRITY", n.location(), "plain archive read failed: "+copyErr.Error())
	}
	if closeErr != nil {
		return closeErr
	}
	if n.byteLength >= 0 && counter.n != n.byteLength {
		return fail("INPUT_CHANGED", n.location(), "archive length changed during plain digest")
	}
	return nil
}

func (n *namespace) childrenOf() map[string][]*entry {
	m := map[string][]*entry{}
	for p, e := range n.entries {
		if p != "" && e.included {
			d := path.Dir(p)
			if d == "." {
				d = ""
			}
			m[d] = append(m[d], e)
		}
	}
	return m
}
func (n *namespace) git(s selection) ([]byte, error) {
	children := n.childrenOf()
	ids := map[string][]byte{}
	nonempty := map[string]bool{}
	keys := sortedKeys(n.entries)
	sort.Slice(keys, func(i, j int) bool {
		return strings.Count(keys[i], "/") > strings.Count(keys[j], "/") || strings.Count(keys[i], "/") == strings.Count(keys[j], "/") && keys[i] > keys[j]
	})
	keys = append(keys, "")
	for _, p := range keys {
		e := n.entries[p]
		if e == nil || e.kind != 'd' || !e.included {
			continue
		}
		list := children[p]
		sort.Slice(list, func(i, j int) bool {
			a, b := path.Base(list[i].name), path.Base(list[j].name)
			if list[i].kind == 'd' {
				a += "/"
			}
			if list[j].kind == 'd' {
				b += "/"
			}
			return a < b
		})
		var b bytes.Buffer
		for _, c := range list {
			mode := "100644"
			v := c.blob[s.algorithm]
			switch c.kind {
			case 'd':
				if s.scheme == "gittree" && !nonempty[c.name] {
					continue
				}
				mode = "40000"
				v = ids[c.name]
			case 'l':
				mode = "120000"
			default:
				exec := c.mode&0100 != 0
				if s.scheme == "swhid" {
					exec = c.mode&0111 != 0
				}
				if exec {
					mode = "100755"
				}
			}
			_, _ = fmt.Fprintf(&b, "%s %s%c", mode, path.Base(c.name), 0)
			b.Write(v)
		}
		ids[p] = object(s.algorithm, "tree", b.Bytes())
		nonempty[p] = b.Len() > 0
	}
	return ids[""], nil
}
func narString(w io.Writer, b []byte) error {
	var header [8]byte
	binary.LittleEndian.PutUint64(header[:], uint64(len(b)))
	if _, e := w.Write(header[:]); e != nil {
		return e
	}
	if _, e := w.Write(b); e != nil {
		return e
	}
	_, e := w.Write(make([]byte, (-len(b))&7))
	return e
}
func narToken(w io.Writer, s string) error { return narString(w, []byte(s)) }
func (n *namespace) writeNAR(w io.Writer) error {
	if err := narToken(w, "nix-archive-1"); err != nil {
		return err
	}
	children := n.childrenOf()
	for p := range children {
		sort.Slice(children[p], func(i, j int) bool { return path.Base(children[p][i].name) < path.Base(children[p][j].name) })
	}
	type action struct {
		token  string
		node   *entry
		isNode bool
	}
	stack := []action{{node: n.entries[""], isNode: true}}
	for len(stack) > 0 {
		a := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !a.isNode {
			if err := narToken(w, a.token); err != nil {
				return err
			}
			continue
		}
		e := a.node
		for _, t := range []string{"(", "type"} {
			if err := narToken(w, t); err != nil {
				return err
			}
		}
		switch e.kind {
		case 'd':
			if err := narToken(w, "directory"); err != nil {
				return err
			}
			stack = append(stack, action{token: ")"})
			list := children[e.name]
			for i := len(list) - 1; i >= 0; i-- {
				c := list[i]
				stack = append(stack, action{token: ")"}, action{node: c, isNode: true}, action{token: "node"}, action{token: path.Base(c.name)}, action{token: "name"}, action{token: "("}, action{token: "entry"})
			}
		case 'l':
			for _, t := range []string{"symlink", "target"} {
				if err := narToken(w, t); err != nil {
					return err
				}
			}
			if err := narString(w, e.target); err != nil {
				return err
			}
			if err := narToken(w, ")"); err != nil {
				return err
			}
		default:
			if err := narToken(w, "regular"); err != nil {
				return err
			}
			if e.mode&0100 != 0 {
				if err := narToken(w, "executable"); err != nil {
					return err
				}
				if err := narToken(w, ""); err != nil {
					return err
				}
			}
			if err := narToken(w, "contents"); err != nil {
				return err
			}
			var header [8]byte
			binary.LittleEndian.PutUint64(header[:], uint64(e.size))
			if _, err := w.Write(header[:]); err != nil {
				return err
			}
			r, err := e.open()
			if err != nil {
				return err
			}
			source := io.Reader(r)
			if n.engine.o.ctx != nil {
				source = &contextReader{r: r, ctx: n.engine.o.ctx, location: n.location()}
			}
			copied, err := io.CopyBuffer(w, source, make([]byte, 32768))
			closeErr := r.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if copied != e.size {
				return fail("INPUT_CHANGED", n.entryLocation(e.original), "file size changed during NAR serialization")
			}
			if _, err = w.Write(make([]byte, (-e.size)&7)); err != nil {
				return err
			}
			if err = narToken(w, ")"); err != nil {
				return err
			}
		}
	}
	return nil
}
