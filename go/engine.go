package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

type engine struct {
	o                 *options
	entries, expanded uint64
	h1, git           bool
	rawAlgs, blobAlgs []string
	checks            []func() error
	cleanups          []func()
	spoolMemory       int64
	selectedRoot      string
	filesystemInput   bool
	budgetMu          sync.Mutex
	spoolMu           sync.Mutex
	warningMu         sync.Mutex
	warnings          map[string]string
}

func (e *engine) addCleanup(cleanup func()) {
	e.spoolMu.Lock()
	defer e.spoolMu.Unlock()
	e.cleanups = append(e.cleanups, cleanup)
}

func (e *engine) addWarning(code, location, reason string) {
	e.warningMu.Lock()
	defer e.warningMu.Unlock()
	if e.warnings == nil {
		e.warnings = map[string]string{}
	}
	e.warnings[code+" "+location] = code + ": " + diagnosticText(location) + ": " + reason
}

func (e *engine) warningMessages() []string {
	e.warningMu.Lock()
	defer e.warningMu.Unlock()
	keys := sortedKeys(e.warnings)
	messages := make([]string, 0, len(keys))
	for _, key := range keys {
		messages = append(messages, e.warnings[key])
	}
	return messages
}

func (e *engine) cleanup() {
	e.spoolMu.Lock()
	cleanups := e.cleanups
	e.cleanups = nil
	e.spoolMu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

func newEngine(o *options) *engine {
	e := &engine{o: o}
	raw, blob := map[string]bool{}, map[string]bool{}
	for _, s := range o.selected {
		if s.scheme == "h1" || s.scheme == "h1-go" {
			e.h1 = true
			raw[s.algorithm] = true
		}
		if s.scheme == "gittree" || s.scheme == "swhid" {
			e.git = true
			blob[s.algorithm] = true
		}
	}
	e.rawAlgs = sortedKeys(raw)
	e.blobAlgs = sortedKeys(blob)
	return e
}
func (e *engine) chargeEntries(n uint64, location string) error {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	if n > e.o.entries-e.entries {
		return fail("LIMIT_EXCEEDED", location, "entry limit exceeded")
	}
	e.entries += n
	return nil
}
func (e *engine) chargeExpanded(n uint64, location string) error {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	if n > e.o.expanded-e.expanded {
		return fail("LIMIT_EXCEEDED", location, "expanded byte limit exceeded")
	}
	e.expanded += n
	return nil
}
func (e *engine) newNamespace(chain []string, typ string, open opener, depth uint64, top bool) (*namespace, error) {
	if top && typ == "directory" {
		e.filesystemInput = true
	}
	if depth > e.o.depth {
		return nil, fail("LIMIT_EXCEEDED", e.diagnosticLocation(chain), "archive depth limit exceeded")
	}
	if depth > 1024 {
		return nil, fail("LIMIT_EXCEEDED", e.diagnosticLocation(chain), "archive nesting exceeds the bounded decoder-stack representation")
	}
	root := func() *entry { return &entry{kind: 'd', included: true} }
	return &namespace{engine: e, chain: append([]string{}, chain...), inputType: typ, entries: map[string]*entry{"": root()}, original: map[string]*entry{"": root()}, opener: open, depth: depth, top: top}, nil
}
func (e *engine) execute() ([]record, error) {
	defer e.cleanup()
	if e.o.ctx == nil {
		e.o.ctx = context.Background()
	}
	if e.o.ctx.Err() != nil {
		return nil, fail("IO_ERROR", e.o.source, "operation cancelled")
	}
	source := e.o.source
	local := source
	if strings.HasPrefix(strings.ToLower(source), "http:") || strings.HasPrefix(strings.ToLower(source), "https:") {
		var cleanup func()
		var err error
		local, cleanup, err = e.download()
		if err != nil {
			return nil, err
		}
		// Registered first so it runs last, after archive handles on the payload are closed.
		e.addCleanup(cleanup)
	} else if strings.Contains(source, "://") {
		return nil, fail("UNSUPPORTED_FORMAT", source, "only HTTP and HTTPS URLs are supported")
	}
	resolved, err := filepath.EvalSymlinks(local)
	if err != nil {
		return nil, fail("IO_ERROR", source, "cannot resolve selected input")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fail("IO_ERROR", source, "cannot establish absolute resolved input root")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fail("IO_ERROR", source, "cannot inspect selected input")
	}
	var n *namespace
	if info.IsDir() {
		if e.hasScheme("plain") {
			return nil, fail("UNSUPPORTED_FORMAT", source, "plain digests require an archive input")
		}
		e.selectedRoot = resolved
		if e.o.stripSet {
			return nil, &failure{"USAGE_ERROR", source, "--strip-components requires an archive input", 2}
		}
		n, err = e.newNamespace(nil, "directory", nil, 0, true)
		if err == nil {
			err = e.directory(n, resolved)
		}
	} else {
		if !info.Mode().IsRegular() {
			return nil, fail("SPECIAL_FILE", source, "selected input is not a regular archive")
		}
		open := stableOpener(resolved, info, source)
		e.checks = append(e.checks, func() error {
			after, err := os.Stat(resolved)
			if err != nil || !sameInfo(info, after) {
				return fail("INPUT_CHANGED", source, "selected archive changed")
			}
			return nil
		})
		r, openErr := open()
		if openErr != nil {
			return nil, openErr
		}
		var first [4]byte
		firstN, _ := io.ReadFull(r, first[:])
		b := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(first[:firstN]), r), 65536)
		typ, detectErr := detect(b, source, true)
		if detectErr != nil {
			_ = r.Close()
			return nil, at(detectErr, source)
		}
		n, err = e.newNamespace(nil, typ, open, 0, true)
		if n != nil {
			n.byteLength = info.Size()
		}
		if err == nil {
			if typ == "zip" {
				_ = r.Close()
				err = e.seekZIP(n, resolved, info.Size())
			} else {
				err = e.archive(n, b)
				closeErr := r.Close()
				if err == nil {
					err = closeErr
				}
			}
		} else {
			_ = r.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	var records []record
	stack := []*namespace{n}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		rs, err := current.hashes()
		if err != nil {
			return nil, err
		}
		records = append(records, rs...)
		if e.o.recurse {
			sort.Slice(current.children, func(i, j int) bool {
				return current.children[i].chain[len(current.children[i].chain)-1] < current.children[j].chain[len(current.children[j].chain)-1]
			})
			for i := len(current.children) - 1; i >= 0; i-- {
				stack = append(stack, current.children[i])
			}
		}
	}
	for _, check := range e.checks {
		if err := check(); err != nil {
			return nil, err
		}
		if e.o.ctx.Err() != nil {
			return nil, fail("IO_ERROR", e.o.source, "operation cancelled")
		}
	}
	return records, nil
}
func sameInfo(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && reflect.DeepEqual(changeStamp(a), changeStamp(b))
}
func changeStamp(info os.FileInfo) any {
	value := reflect.ValueOf(info.Sys())
	if value.IsValid() && value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		field := value.FieldByName(name)
		if field.IsValid() && field.CanInterface() {
			return field.Interface()
		}
	}
	return nil
}

type checkedFile struct {
	*os.File
	before   os.FileInfo
	location string
}

func (f *checkedFile) Close() error {
	after, err := f.Stat()
	closeErr := f.File.Close()
	if err != nil {
		return fail("IO_ERROR", f.location, "cannot inspect input after read")
	}
	if !sameInfo(f.before, after) {
		return fail("INPUT_CHANGED", f.location, "input changed during read")
	}
	return closeErr
}
func stableOpener(p string, before os.FileInfo, location string) opener {
	return func() (io.ReadCloser, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, fail("IO_ERROR", location, "cannot open input")
		}
		now, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if !sameInfo(before, now) {
			_ = f.Close()
			return nil, fail("INPUT_CHANGED", location, "input changed before read")
		}
		return &checkedFile{f, before, location}, nil
	}
}
func inventory(root string) (map[string]os.FileInfo, error) {
	m := map[string]os.FileInfo{}
	stack := []string{""}
	for len(stack) > 0 {
		relative := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		full := filepath.Join(root, relative)
		info, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		m[relative] = info
		if info.IsDir() {
			if err := checkDirectoryNames(full); err != nil {
				return nil, err
			}
			list, err := os.ReadDir(full)
			if err != nil {
				return nil, err
			}
			for i := len(list) - 1; i >= 0; i-- {
				stack = append(stack, filepath.Join(relative, list[i].Name()))
			}
		}
	}
	return m, nil
}
func (e *engine) directory(n *namespace, root string) error {
	before, err := inventory(root)
	if err != nil {
		return fail("IO_ERROR", n.location(), "cannot enumerate directory")
	}
	e.checks = append(e.checks, func() error {
		after, err := inventory(root)
		if err != nil || len(after) != len(before) {
			return fail("INPUT_CHANGED", n.location(), "directory inventory changed")
		}
		for p, a := range before {
			b := after[p]
			if b == nil || !sameInfo(a, b) {
				return fail("INPUT_CHANGED", n.entryLocation(filepath.ToSlash(p)), "directory entry changed")
			}
		}
		return nil
	})
	for _, relative := range sortedKeys(before) {
		if relative == "" {
			continue
		}
		info := before[relative]
		p := filepath.ToSlash(relative)
		full := filepath.Join(root, relative)
		kind := byte('f')
		switch {
		case info.IsDir():
			kind = 'd'
		case info.Mode()&os.ModeSymlink != 0:
			kind = 'l'
		case !info.Mode().IsRegular():
			return fail("SPECIAL_FILE", n.entryLocation(p), "unsupported filesystem entry")
		}
		ent, err := n.add(p, kind, uint32(info.Mode().Perm()), info.Size(), stableOpener(full, info, n.entryLocation(p)))
		if err != nil {
			return err
		}
		if kind == 'd' {
			continue
		}
		if kind == 'l' {
			if err = checkLinkEncoding(full); err != nil {
				return err
			}
			target, err := os.Readlink(full)
			if err != nil {
				return fail("IO_ERROR", n.entryLocation(p), "cannot read symbolic link")
			}
			ent.target = []byte(target)
			ent.size = int64(len(ent.target))
			if err = e.payload(n, ent, bytes.NewReader(ent.target), false, false); err != nil {
				return err
			}
			if ent.included && e.hasScheme("h1-go") {
				actual, err := filepath.EvalSymlinks(full)
				if err != nil {
					return fail("DANGLING_SYMLINK", n.entryLocation(p), "cannot resolve h1-go read target")
				}
				rel, err := filepath.Rel(root, actual)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fail("UNSAFE_SYMLINK", n.entryLocation(p), "h1-go read target escapes root")
				}
				targetInfo, err := os.Stat(actual)
				if err != nil || !targetInfo.Mode().IsRegular() {
					return fail("UNSAFE_SYMLINK", n.entryLocation(p), "h1-go target is not a regular file")
				}
				r, err := stableOpener(actual, targetInfo, n.entryLocation(p))()
				if err != nil {
					return err
				}
				writers := []io.Writer{}
				hs := map[string]hash.Hash{}
				for _, a := range e.rawAlgs {
					h := digest(a)
					hs[a] = h
					writers = append(writers, h)
				}
				_, err = io.CopyBuffer(io.MultiWriter(writers...), r, make([]byte, 32768))
				ce := r.Close()
				if err != nil {
					return err
				}
				if ce != nil {
					return ce
				}
				ent.goRaw = map[string][]byte{}
				for a, h := range hs {
					ent.goRaw[a] = h.Sum(nil)
				}
			}
		} else {
			r, err := ent.open()
			if err != nil {
				return err
			}
			err = e.payload(n, ent, r, false, true)
			ce := r.Close()
			if err != nil {
				return err
			}
			if ce != nil {
				return ce
			}
		}
	}
	return n.validate()
}
func (e *engine) hasScheme(s string) bool {
	for _, v := range e.o.selected {
		if v.scheme == s {
			return true
		}
	}
	return false
}
func (e *engine) onlyNAR() bool {
	for _, s := range e.o.selected {
		if s.scheme != "nar" {
			return false
		}
	}
	return len(e.o.selected) > 0
}
func validUTF8(s string) bool { return utf8.ValidString(s) }
func (e *engine) payload(n *namespace, ent *entry, r io.Reader, archive, discover bool) error {
	if e.o.ctx != nil {
		r = &contextReader{r: r, ctx: e.o.ctx, location: n.location()}
	}
	if archive && ent.kind != 'h' && ent.size >= 0 {
		if err := e.chargeExpanded(uint64(ent.size), n.location()); err != nil {
			return err
		}
	}
	raw, blob := map[string]hash.Hash{}, map[string]hash.Hash{}
	writers := []io.Writer{}
	if (n.top || e.o.recurse) && (ent.included || ent.kind == 'f') { // Excluded TAR targets may be referenced by included hard links.
		for _, a := range e.rawAlgs {
			h := digest(a)
			raw[a] = h
			writers = append(writers, h)
		}
		for _, a := range e.blobAlgs {
			if ent.size < 0 {
				return fail("UNSUPPORTED_STREAMING", n.entryLocation(ent.original), "blob length is unavailable before streaming payload")
			}
			h := digest(a)
			_, _ = fmt.Fprintf(h, "blob %d%c", ent.size, 0)
			blob[a] = h
			writers = append(writers, h)
		}
	}
	counter := &countWriter{}
	writers = append(writers, counter)
	if archive && ent.size < 0 {
		writers = append(writers, &expansionWriter{engine: e, location: n.location()})
	}
	stream := io.TeeReader(r, io.MultiWriter(writers...))
	b := bufio.NewReaderSize(stream, 65536)
	if ent.kind == 'f' && discover && (e.o.strict || e.o.recurse) {
		ent.archiveHint, _ = detect(b, "", false)
	}
	if ent.included && ent.kind == 'f' && discover && (e.o.strict || e.o.recurse) {
		typ, err := detect(b, ent.original, false)
		if err != nil {
			if n.inputType == "zip" && !n.top {
				ent.discoveryError = at(err, n.entryLocation(ent.original))
			} else {
				return at(err, n.entryLocation(ent.original))
			}
		}
		if typ != "" {
			chain := append(append([]string{}, n.chain...), ent.original)
			child, err := e.newNamespace(chain, typ, ent.open, n.depth+1, false)
			if err != nil {
				return err
			}
			child.byteLength = ent.size
			child.seekable = ent.seekOnly || n.inputType == "directory"
			var childSource io.Reader = b
			if child.seekable {
				probe, probeErr := child.opener()
				if probeErr != nil {
					return probeErr
				}
				_, child.seekable = probe.(io.ReaderAt)
				if closeErr := probe.Close(); closeErr != nil {
					return closeErr
				}
			}
			if !child.seekable {
				open, size, err := e.spoolArchive(b, ent.size, child.location())
				if err != nil {
					return err
				}
				child.opener = open
				child.byteLength = size
				child.seekable = true
				spooled, err := open()
				if err != nil {
					return err
				}
				defer func() { _ = spooled.Close() }()
				childSource = spooled
			}
			if typ == "zip" {
				if child.seekable {
					err = e.seekZIP(child, "", child.byteLength)
				} else {
					err = e.archive(child, childSource)
				}
			} else {
				err = e.archive(child, childSource)
			}
			if err != nil {
				return err
			}
			n.children = append(n.children, child)
		}
	}
	if _, err := io.CopyBuffer(io.Discard, b, make([]byte, 32768)); err != nil {
		var f *failure
		if errors.As(err, &f) {
			return err
		}
		return fail("ARCHIVE_INTEGRITY", n.entryLocation(ent.original), "payload decoding failed: "+err.Error())
	}
	if ent.size >= 0 && counter.n != ent.size {
		return fail("ARCHIVE_INTEGRITY", n.entryLocation(ent.original), "payload length disagrees with metadata")
	}
	if ent.size < 0 {
		ent.size = counter.n
	}
	ent.raw = map[string][]byte{}
	ent.blob = map[string][]byte{}
	for a, h := range raw {
		ent.raw[a] = h.Sum(nil)
	}
	for a, h := range blob {
		ent.blob[a] = h.Sum(nil)
	}
	return nil
}

type countWriter struct{ n int64 }
type contextReader struct {
	r        io.Reader
	ctx      context.Context
	location string
}

func (r *contextReader) Read(b []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, fail("IO_ERROR", r.location, "operation cancelled")
	}
	return r.r.Read(b)
}

type expansionWriter struct {
	engine   *engine
	location string
}

func (w *expansionWriter) Write(b []byte) (int, error) {
	if err := w.engine.chargeExpanded(uint64(len(b)), w.location); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *countWriter) Write(b []byte) (int, error) { w.n += int64(len(b)); return len(b), nil }
func (e *engine) archive(n *namespace, r io.Reader) error {
	switch n.inputType {
	case "zip":
		return e.streamZIP(n, r)
	case "tar", "tar.gz":
		return e.readTAR(n, r)
	}
	return fail("UNSUPPORTED_FORMAT", n.location(), "unsupported archive format")
}
func suffixType(name string) string {
	s := strings.ToLower(name)
	for _, x := range []string{".zip", ".jar", ".war", ".ear"} {
		if strings.HasSuffix(s, x) {
			return "zip"
		}
	}
	if strings.HasSuffix(s, ".tar.gz") || strings.HasSuffix(s, ".tgz") {
		return "tar.gz"
	}
	if strings.HasSuffix(s, ".tar") {
		return "tar"
	}
	return ""
}
func detect(r *bufio.Reader, name string, required bool) (string, error) {
	b, _ := r.Peek(1024)
	typ := ""
	if plausibleZIP(b) {
		typ = "zip"
	}
	if len(b) >= 10 && b[0] == 31 && b[1] == 139 && b[2] == 8 && b[3]&0xe0 == 0 {
		if gzipContainsTARHeader(r) {
			typ = "tar.gz"
		}
	}
	if len(b) >= 512 && tarHeaderPrefix(b) {
		typ = "tar"
	}
	expected := suffixType(name)
	if expected != "" && typ != expected {
		return "", fail("ARCHIVE_INTEGRITY", "", "archive suffix does not match valid archive content")
	}
	if typ == "" && required {
		return "", fail("UNSUPPORTED_FORMAT", "", "selected file is not a supported archive")
	}
	return typ, nil
}

func tarHeaderPrefix(b []byte) bool {
	return len(b) >= 512 && validTARHeader(b[:512]) &&
		(!bytes.Equal(b[:512], make([]byte, 512)) || len(b) >= 1024 && bytes.Equal(b[512:1024], make([]byte, 512)))
}

func gzipContainsTARHeader(r *bufio.Reader) bool {
	compressed, _ := r.Peek(65536)
	if len(compressed) < 10 {
		return false
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return false
	}
	gz.Multistream(false)
	defer func() { _ = gz.Close() }()
	prefix := make([]byte, 1024)
	n, _ := io.ReadFull(gz, prefix)
	return tarHeaderPrefix(prefix[:n])
}

func plausibleZIP(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch u32(b) {
	case 0x04034b50:
		return len(b) >= 30 && u16(b[4:]) >= 10 && u16(b[26:]) > 0
	case 0x06054b50:
		return len(b) >= 22 && u16(b[8:]) == 0 && u16(b[10:]) == 0 && u32(b[12:]) == 0 && u32(b[16:]) == 0
	case 0x06064b50:
		return len(b) >= 56 && u64(b[4:]) >= 44 && u64(b[24:]) == 0 && u64(b[32:]) == 0 && u64(b[40:]) == 0 && u64(b[48:]) == 0
	}
	return false
}
