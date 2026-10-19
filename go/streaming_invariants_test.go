package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"testing"
)

type metadataOnlyZIP struct {
	*bytes.Reader
	start, end int64
}

func (r *metadataOnlyZIP) ReadAt(b []byte, offset int64) (int, error) {
	if offset < r.end && offset+int64(len(b)) > r.start {
		return 0, fmt.Errorf("ZIP metadata preflight reread compressed payload")
	}
	return r.Reader.ReadAt(b, offset)
}
func (r *metadataOnlyZIP) Close() error { return nil }

func TestZIPPreflightReadsOnlyStructuralRanges(t *testing.T) {
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{bytes.Repeat([]byte("payload"), 100)})
	directory := int64(u32(raw[len(raw)-6:]))
	payload := int64(30 + int(u16(raw[26:])) + int(u16(raw[28:])))
	options, err := parse([]string{"--h1", "input.zip"})
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(options)
	t.Cleanup(engine.cleanup)
	open := func() (io.ReadCloser, error) {
		return &metadataOnlyZIP{Reader: bytes.NewReader(raw), start: payload, end: directory - 16}, nil
	}
	tree, err := engine.newNamespace(nil, "zip", open, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	tree.seekable = true
	tree.byteLength = int64(len(raw))
	if err := engine.preflightZIP(tree); err != nil {
		t.Fatal(err)
	}
}

func TestSequentialPreflightNeverReopensPayload(t *testing.T) {
	data := nestedZIPGzip(t, makeZIP(t, 8, []string{"a"}, [][]byte{[]byte("A")}))
	options, err := parse([]string{"--h1", "--strict", "--recurse", "input.tgz"})
	if err != nil {
		t.Fatal(err)
	}

	engine := newEngine(options)
	t.Cleanup(engine.cleanup)
	reopens := 0
	open := func() (io.ReadCloser, error) {
		reopens++
		return nil, fmt.Errorf("non-NAR sequential source was reopened")
	}
	tree, err := engine.newNamespace(nil, "tar.gz", open, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.archive(tree, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if reopens != 0 {
		t.Fatalf("metadata-only preflight reread sequential payload %d times", reopens)
	}
}

func TestForwardSequentialAliasChainsAndExclusions(t *testing.T) {
	var inner bytes.Buffer
	writer := tar.NewWriter(&inner)
	if err := writer.WriteHeader(&tar.Header{Name: "a", Mode: 0644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var outer bytes.Buffer
	writer = tar.NewWriter(&outer)
	for name, target := range map[string]string{"one.tar": "chain.bin", "chain.bin": "payload.bin", "two.bin": "payload.bin"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.WriteHeader(&tar.Header{Name: "payload.bin", Mode: 0644, Size: int64(inner.Len())}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(outer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	dir := workspace(t)
	seekable := writeFixture(t, dir, "seekable.tar", outer.Bytes())
	sequential := writeFixture(t, dir, "sequential.tgz", compressed.Bytes())
	flags := []string{"--h1", "--gittree", "--swhid", "--strict", "--recurse", "--exclude=payload.bin", "--exclude=one.tar!/a", "--format=json"}
	want := invoke(t, append(flags, seekable)...)
	got := invoke(t, append(flags, sequential)...)
	if len(got) != 12 || len(want) != len(got) {
		t.Fatal("alias chains or content-based alias discovery omitted a namespace")
	}
	for i := range got {
		if got[i].Value != want[i].Value || fmt.Sprint(got[i].ArchiveEntries) != fmt.Sprint(want[i].ArchiveEntries) {
			t.Fatal("forward alias fan-out changed content, boundary exclusion, or ordering")
		}
	}
	rejected(t, 1, "LIMIT_EXCEEDED", "--h1", "--recurse", "--max-entries=4", sequential)
	options, err := parse(append(flags, sequential))
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(options)
	t.Cleanup(engine.cleanup)
	reopens := 0
	open := func() (io.ReadCloser, error) {
		reopens++
		return nil, fmt.Errorf("forward alias unexpectedly reopened its sequential source")
	}
	tree, err := engine.newNamespace(nil, "tar.gz", open, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.archive(tree, bytes.NewReader(compressed.Bytes())); err != nil {
		t.Fatal(err)
	}
	if reopens != 0 {
		t.Fatal("forward alias discovery reread a non-NAR original payload")
	}
}
