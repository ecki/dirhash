package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	godirhash "golang.org/x/mod/sumdb/dirhash"
)

const slashWarningReason = ": accepted empty ZIP directory with repeated trailing slashes\n"

var slashSelectors = []string{"--h1", "--h1:sha512", "--gittree", "--gittree:sha256", "--swhid", "--nar", "--nar:sha512"}

func runCaptured(args ...string) (int, string, string) {
	var out, diagnostics bytes.Buffer
	status := run(args, &out, &diagnostics)
	return status, out.String(), diagnostics.String()
}

func valuesByScheme(records []record) map[string]string {
	m := map[string]string{}
	for _, r := range records {
		m[strings.Join(r.ArchiveEntries, "|")+" "+r.Scheme+":"+r.DigestAlgorithm] = r.Value
	}
	return m
}

func TestZIPRepeatedTrailingSlashDirectoryCompatibility(t *testing.T) {
	dir := workspace(t)
	repeated := makeZIP(t, 8, []string{"9/java.activation//", "9/a.txt"}, [][]byte{nil, []byte("x")})
	single := makeZIP(t, 8, []string{"9/java.activation/", "9/a.txt"}, [][]byte{nil, []byte("x")})
	repeatedPath := writeFixture(t, dir, "ct.sym", repeated)
	singlePath := writeFixture(t, dir, "single.zip", single)
	location := repeatedPath + "!/9/java.activation//"

	status, stdout, stderr := runCaptured(append(append([]string{}, slashSelectors...), "--h1-go", "--plain", "--format=json", repeatedPath)...)
	if status != 0 || stdout == "" || stderr != "WARN_ZIP_DIRECTORY_SLASH: "+location+slashWarningReason {
		t.Fatalf("non-strict status=%d stderr=%q", status, stderr)
	}
	got := valuesByScheme(invoke(t, append(append([]string{}, slashSelectors...), "--format=json", repeatedPath)...))
	want := valuesByScheme(invoke(t, append(append([]string{}, slashSelectors...), "--format=json", singlePath)...))
	if len(got) != len(slashSelectors) || len(got) != len(want) {
		t.Fatalf("unexpected result counts got=%v want=%v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s: repeated slash %s != single slash %s", key, got[key], value)
		}
	}
	rawGo, err := godirhash.HashZip(repeatedPath, godirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	if h1go := invoke(t, "--h1-go", "--format=json", repeatedPath); h1go[0].Value != rawGo {
		t.Fatalf("h1-go did not preserve raw ZIP name: %s != %s", h1go[0].Value, rawGo)
	}
	sum := sha256.Sum256(repeated)
	if p := invoke(t, "--plain", "--format=json", repeatedPath); p[0].Value != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("plain value changed: %s", p[0].Value)
	}

	// Exclusion of the marker still validates and warns; results match the single-slash form.
	status, _, stderr = runCaptured("--h1", "--exclude=9/java.activation", "--format=json", repeatedPath)
	if status != 0 || strings.Count(stderr, "WARN_ZIP_DIRECTORY_SLASH") != 1 {
		t.Fatalf("excluded marker status=%d stderr=%q", status, stderr)
	}
	if a, b := invoke(t, "--h1", "--gittree", "--exclude=9/java.activation", "--format=json", repeatedPath), invoke(t, "--h1", "--gittree", "--exclude=9/java.activation", "--format=json", singlePath); a[0].Value != b[0].Value || a[1].Value != b[1].Value {
		t.Fatalf("excluded results differ: %#v %#v", a, b)
	}
	if a, b := invoke(t, "--h1", "--nar", "--strip-components=1", "--format=json", repeatedPath), invoke(t, "--h1", "--nar", "--strip-components=1", "--format=json", singlePath); a[0].Value != b[0].Value || a[1].Value != b[1].Value {
		t.Fatalf("stripped results differ: %#v %#v", a, b)
	}

	// Direct root marker.
	rootMarker := writeFixture(t, dir, "root-marker.zip", makeZIP(t, 0, []string{"a//"}, [][]byte{nil}))
	rootSingle := writeFixture(t, dir, "root-single.zip", makeZIP(t, 0, []string{"a/"}, [][]byte{nil}))
	if a, b := invoke(t, "--gittree", "--nar", "--format=json", rootMarker), invoke(t, "--gittree", "--nar", "--format=json", rootSingle); a[0].Value != b[0].Value || a[1].Value != b[1].Value {
		t.Fatalf("root marker results differ: %#v %#v", a, b)
	}

	// Strict mode rejects without a warning.
	for _, path := range []string{repeatedPath, rootMarker} {
		status, stdout, stderr = runCaptured("--h1", "--strict", path)
		if status != 1 || stdout != "" || !strings.HasPrefix(stderr, "INVALID_PATH") || strings.Contains(stderr, "WARN_") {
			t.Fatalf("strict status=%d stdout=%q stderr=%q", status, stdout, stderr)
		}
	}

	// Nested and directory-contained archives warn once per logical occurrence, including NAR rereads.
	outer := writeFixture(t, dir, "outer.tar", plainTAR(t, "inner.zip", repeated))
	args := append(append([]string{}, slashSelectors...), "--h1-go", "--plain", "--recurse", "--format=json", outer)
	status, stdout, stderr = runCaptured(args...)
	if status != 0 || stdout == "" || stderr != "WARN_ZIP_DIRECTORY_SLASH: "+outer+"!/inner.zip!/9/java.activation//"+slashWarningReason {
		t.Fatalf("nested status=%d stderr=%q", status, stderr)
	}
	status, stdout, stderr = runCaptured("--nar", "--strict", "--recurse", outer)
	if status != 1 || stdout != "" || !strings.HasPrefix(stderr, "INVALID_PATH") {
		t.Fatalf("nested strict status=%d stderr=%q", status, stderr)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0700); err != nil {
		t.Fatal(err)
	}
	_ = writeFixture(t, tree, "ct.sym", repeated)
	status, stdout, stderr = runCaptured("--h1", "--nar", "--recurse", "--format=json", tree)
	if status != 0 || stdout == "" || strings.Count(stderr, "WARN_ZIP_DIRECTORY_SLASH") != 1 || !strings.Contains(stderr, "!/9/java.activation//: accepted") {
		t.Fatalf("directory-contained status=%d stderr=%q", status, stderr)
	}
}

func TestZIPRepeatedTrailingSlashNearMissesStillFail(t *testing.T) {
	dir := workspace(t)
	cases := []struct {
		names    []string
		contents [][]byte
		code     string
	}{
		{[]string{"//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"a//b//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"a//b/"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"/a//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"a/.//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"a/..//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"a\\b//"}, [][]byte{nil}, "INVALID_PATH"},
		{[]string{"aXX"}, [][]byte{[]byte("x")}, "INVALID_PATH"},
		{[]string{"a//", "a"}, [][]byte{nil, []byte("x")}, "DUPLICATE_ENTRY"},
		{[]string{"a//", "a/"}, [][]byte{nil, nil}, "DUPLICATE_ENTRY"},
	}
	for i, c := range cases {
		path := writeFixture(t, dir, "near"+string(rune('a'+i))+".zip", bytes.ReplaceAll(makeZIP(t, 0, c.names, c.contents), []byte("aXX"), []byte("a//")))
		status, stdout, stderr := runCaptured("--h1", path)
		if status != 1 || stdout != "" || !strings.HasPrefix(stderr, c.code) || strings.Contains(stderr, "WARN_") {
			t.Errorf("%q: status=%d stdout=%q stderr=%q", c.names, status, stdout, stderr)
		}
	}

	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "a//", Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	status, stdout, stderr := runCaptured("--h1", writeFixture(t, dir, "slash.tar", b.Bytes()))
	if status != 1 || stdout != "" || !strings.HasPrefix(stderr, "INVALID_PATH") || strings.Contains(stderr, "WARN_") {
		t.Fatalf("TAR repeated slash was relaxed: status=%d stderr=%q", status, stderr)
	}
}
