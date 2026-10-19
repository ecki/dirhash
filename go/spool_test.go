package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestArchiveMemoryPartialBlockAfterAnotherSourceReleased(t *testing.T) {
	engine := newEngine(&options{})
	engine.spoolMemory = archiveMemoryLimit - 1000
	second := &archiveMemory{engine: engine}
	defer second.release()
	if !second.write(make([]byte, 1000)) {
		t.Fatal("initial bounded allocation failed")
	}
	engine.spoolMemory -= archiveMemoryLimit - 1000
	if second.write([]byte("more")) {
		t.Fatal("partial terminal block should spill instead of growing invalid block offsets")
	}
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp(".", ".dirhash-os-temp-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		if err := os.Setenv(key, absolute); err != nil {
			_ = os.RemoveAll(dir)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	status := m.Run()
	_ = os.RemoveAll(absolute)
	os.Exit(status)
}

type cancelArchiveReader struct {
	*bytes.Reader
	cancel context.CancelFunc
	reads  int
}

type shortArchiveReader struct{ io.Reader }

func (r shortArchiveReader) Read(b []byte) (int, error) {
	return r.Reader.Read(b[:min(len(b), 137)])
}

func TestNestedArchiveMemoryBoundaryAndUnknownLength(t *testing.T) {
	data := bytes.Repeat([]byte("x"), int(archiveMemoryLimit+1))
	for _, length := range []int64{archiveMemoryLimit, archiveMemoryLimit + 1} {
		for _, known := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-known-%v", length, known), func(t *testing.T) {
				engine := newEngine(&options{})
				t.Cleanup(engine.cleanup)
				expected := int64(-1)
				if known {
					expected = length
				}
				var source io.Reader = bytes.NewReader(data[:length])
				if !known {
					source = shortArchiveReader{source}
				}
				open, size, err := engine.spoolArchive(source, expected, "nested.zip")
				if err != nil || size != length {
					t.Fatalf("size=%d err=%v", size, err)
				}
				reader, err := open()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = reader.Close() }()
				_, inMemory := reader.(*memoryArchiveReader)
				if inMemory != (length <= archiveMemoryLimit) {
					t.Fatalf("memory=%v for length %d", inMemory, length)
				}
				var tail [1]byte
				if _, err := reader.(io.ReaderAt).ReadAt(tail[:], length-1); err != nil || tail[0] != 'x' {
					t.Fatalf("spool content differs: %q %v", tail, err)
				}
				if engine.spoolMemory > archiveMemoryLimit {
					t.Fatal("aggregate memory limit exceeded")
				}
			})
		}
	}
}

func TestNestedArchiveMaterializationRejectsClaimedLengthMismatch(t *testing.T) {
	before := privateArchiveDirectories(t)
	data := bytes.Repeat([]byte("x"), int(archiveMemoryLimit+2))
	for _, expected := range []int64{3, archiveMemoryLimit + 1} {
		for _, difference := range []int64{-1, 1} {
			engine := newEngine(&options{})
			_, _, err := engine.spoolArchive(bytes.NewReader(data[:expected+difference]), expected, "nested.zip")
			if err == nil || !strings.Contains(err.Error(), "ARCHIVE_INTEGRITY") {
				t.Fatalf("expected=%d difference=%d: %v", expected, difference, err)
			}
			engine.cleanup()
		}
	}
	if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("length mismatch leaked private files: before=%v after=%v", before, after)
	}
}

func (r *cancelArchiveReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b[:min(len(b), 512)])
	r.reads++
	if r.reads == 2 {
		r.cancel()
	}
	return n, err
}

func privateArchiveDirectories(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), ".dirhash-archive-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestNestedDeferredZIPAllSchemes(t *testing.T) {
	before := privateArchiveDirectories(t)
	t.Cleanup(func() {
		if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
			t.Fatalf("private archive files leaked: before=%v after=%v", before, after)
		}
	})
	dir := workspace(t)
	inner := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("hello")})
	direct := writeFixture(t, dir, "direct.zip", inner)
	outer := writeFixture(t, dir, "outer.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner}))
	for _, strict := range []bool{false, true} {
		flags := []string{"--format=json"}
		for _, scheme := range schemes {
			for _, algorithm := range algorithms {
				flags = append(flags, "--"+scheme+":"+algorithm)
			}
		}
		if strict {
			flags = append(flags, "--strict")
		}
		want := invoke(t, append(append([]string{}, flags...), direct)...)
		parent := invoke(t, append(append([]string{}, flags...), outer)...)
		got := invoke(t, append(append([]string{}, flags...), "--recurse", outer)...)
		if len(got) != 2*len(want) {
			t.Fatalf("got %d results, want %d", len(got), 2*len(want))
		}
		for i := range want {
			if got[i].Value != parent[i].Value || got[len(want)+i].Value != want[i].Value {
				t.Fatalf("%s parent or nested digest changed", want[i].Scheme)
			}
		}
		budget := fmt.Sprintf("--max-expanded-bytes=%d", len(inner)+len("hello"))
		_ = invoke(t, append(append([]string{}, flags...), "--recurse", budget, outer)...)
		rejected(t, 1, "LIMIT_EXCEEDED", append(append([]string{}, flags...), "--recurse", "--max-expanded-bytes=1", outer)...)
	}
}

func TestNestedArchiveSpoolCleanupOnMalformedAndExcluded(t *testing.T) {
	before := privateArchiveDirectories(t)
	dir := workspace(t)
	inner := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("hello")})
	malformed := append(append([]byte{}, inner...), '!')
	outer := writeFixture(t, dir, "outer.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{malformed}))
	rejected(t, 1, "ARCHIVE_LAYOUT", "--h1", "--gittree", "--strict", "--recurse", outer)
	_ = invoke(t, "--h1", "--gittree", "--recurse", "--exclude=inner.zip", "--format=json", outer)
	if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("private archive files leaked: before=%v after=%v", before, after)
	}
}

func TestNestedArchiveSpoolUsesPrivateFiles(t *testing.T) {
	engine := newEngine(&options{})
	t.Cleanup(engine.cleanup)
	data := bytes.Repeat([]byte("x"), int(archiveMemoryLimit+1))
	open, size, err := engine.spoolArchive(bytes.NewReader(data), int64(len(data)), "nested.zip")
	if err != nil {
		t.Fatal(err)
	}

	if size != int64(len(data)) {
		t.Fatal("wrong spool length")
	}
	reader, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	file := reader.(*checkedFile)
	if info, err := os.Stat(file.Name()); err != nil || info.Mode().Perm()&0077 != 0 && os.PathSeparator != '\\' {
		t.Fatalf("private archive permissions: %v %v", info, err)
	}
}

func TestNestedArchiveSpoolCleanupOnCancellation(t *testing.T) {
	before := privateArchiveDirectories(t)
	o, err := parse([]string{"--h1", "--recurse", "outer.tar"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.ctx = ctx
	engine := newEngine(o)
	t.Cleanup(engine.cleanup)
	tree, err := engine.newNamespace(nil, "tar", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	data := makeZIP(t, zip.Store, []string{"a"}, [][]byte{bytes.Repeat([]byte("a"), int(archiveMemoryLimit+1))})
	entry, err := tree.add("inner.zip", 'f', 0644, int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := &cancelArchiveReader{Reader: bytes.NewReader(data), cancel: cancel}
	if err := engine.payload(tree, entry, reader, true, true); err == nil || !strings.Contains(err.Error(), "IO_ERROR") {
		t.Fatalf("cancellation did not fail archive processing: %v", err)
	}
	if len(privateArchiveDirectories(t)) != len(before)+1 {
		t.Fatal("cancellation did not occur while an archive file existed")
	}
	engine.cleanup()
	if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("cancelled archive files leaked: before=%v after=%v", before, after)
	}
}

func TestNestedArchiveContainingZIPLengthClaims(t *testing.T) {
	before := privateArchiveDirectories(t)
	dir := workspace(t)
	for _, payloadSize := range []int{1, int(archiveMemoryLimit + 1)} {
		inner := makeZIP(t, zip.Store, []string{"a"}, [][]byte{bytes.Repeat([]byte("x"), payloadSize)})
		for _, difference := range []int{-1, 1} {
			outer := makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner})
			central := bytes.Index(outer, []byte("PK\x01\x02"))
			if central < 16 {
				t.Fatal("ZIP central directory missing")
			}
			claimed := uint32(len(inner) + difference)
			binary.LittleEndian.PutUint32(outer[central+24:], claimed)
			binary.LittleEndian.PutUint32(outer[central-4:], claimed)
			path := writeFixture(t, dir, fmt.Sprintf("claim-%d-%d.zip", payloadSize, difference), outer)
			for _, strict := range []bool{false, true} {
				flags := []string{"--h1", "--gittree", "--recurse"}
				if strict {
					flags = append(flags, "--strict")
				}
				rejected(t, 1, "ARCHIVE_INTEGRITY", append(flags, path)...)
			}
		}
	}
	if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("bad containing ZIP claims leaked files: before=%v after=%v", before, after)
	}
}

func TestNestedArchiveDescriptorCentralSizeMismatch(t *testing.T) {
	dir := workspace(t)
	inner := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("hello")})
	central := bytes.Index(inner, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint32(inner[central-4:], 6)
	outer := writeFixture(t, dir, "descriptor.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner}))
	for _, strict := range []bool{false, true} {
		flags := []string{"--h1", "--gittree", "--recurse"}
		if strict {
			flags = append(flags, "--strict")
		}
		rejected(t, 1, "ARCHIVE_LAYOUT", append(flags, outer)...)
	}
}

func TestNestedArchiveSpillBudgetBeforeWrite(t *testing.T) {
	before := privateArchiveDirectories(t)
	limit := archiveMemoryLimit + 65536
	o, err := parse([]string{"--h1", "--recurse", fmt.Sprintf("--max-expanded-bytes=%d", limit), "outer.tar"})
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(o)
	t.Cleanup(engine.cleanup)
	tree, err := engine.newNamespace(nil, "tar", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	data := makeZIP(t, zip.Store, []string{"a"}, [][]byte{bytes.Repeat([]byte("x"), int(archiveMemoryLimit+200000))})
	entry, err := tree.add("inner.zip", 'f', 0644, -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = engine.payload(tree, entry, bytes.NewReader(data), true, true)
	if err == nil || !strings.Contains(err.Error(), "LIMIT_EXCEEDED") {
		t.Fatalf("expanded limit did not stop spool: %v", err)
	}
	after := privateArchiveDirectories(t)
	if len(after) != len(before)+1 {
		t.Fatal("test did not reach a disk spill")
	}
	existing := map[string]bool{}
	for _, directory := range before {
		existing[directory] = true
	}
	for _, directory := range after {
		if existing[directory] {
			continue
		}
		info, err := os.Stat(filepath.Join(directory, "archive"))
		if err != nil || info.Size() > limit {
			t.Fatalf("spool write exceeded limit: %v %v", info, err)
		}
	}

	engine.cleanup()
	if after := privateArchiveDirectories(t); !reflect.DeepEqual(before, after) {
		t.Fatal("limited spool was not cleaned")
	}
}

func TestNestedArchiveDiskSpillInsideSelectedWorkingDirectory(t *testing.T) {
	dir := workspace(t)
	t.Chdir(dir)
	inner := makeZIP(t, zip.Store, []string{"a"}, [][]byte{bytes.Repeat([]byte("x"), int(archiveMemoryLimit+1))})
	_ = writeFixture(t, ".", "outer.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner}))
	want := invoke(t, "--h1", "--format=json", ".")
	got := invoke(t, "--h1", "--recurse", "--format=json", ".")
	if len(got) != 3 || got[0].Value != want[0].Value {
		t.Fatal("own disk spill changed the selected directory tree")
	}
}

func TestNestedArchiveRejectsTemporaryDirectoryInsideSelectedRoot(t *testing.T) {
	dir := workspace(t)
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, root)
	}
	engine := newEngine(&options{})
	engine.selectedRoot = root
	if _, err := engine.privateArchiveDirectory(); err == nil || !strings.Contains(err.Error(), "IO_ERROR") {
		t.Fatalf("unsafe OS temporary directory was accepted: %v", err)
	}
}

func TestNestedArchiveSpillPreservesDirectoryMutationDetection(t *testing.T) {
	dir := workspace(t)
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	o, err := parse([]string{"--h1", root})
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(o)
	t.Cleanup(engine.cleanup)
	engine.selectedRoot = root
	tree, err := engine.newNamespace(nil, "directory", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.directory(tree, root); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.spoolArchive(bytes.NewReader(make([]byte, archiveMemoryLimit+1)), archiveMemoryLimit+1, "nested.zip"); err != nil {
		t.Fatal(err)
	}
	engine.cleanup()
	stamp := time.Now().Add(-time.Hour)
	if err := os.Chtimes(root, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := engine.checks[0](); err == nil || !strings.Contains(err.Error(), "INPUT_CHANGED") {
		t.Fatalf("directory metadata mutation was ignored after disk spill: %v", err)
	}
}
