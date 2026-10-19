package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func plainZIP(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	if err := w.SetComment("comment included in plain digest"); err != nil {
		t.Fatal(err)
	}
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func plainTAR(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func plainGZIP(t *testing.T, contents []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestPlainKnownAnswersAllPrimitivesAndArchiveKinds(t *testing.T) {
	dir := workspace(t)
	tarBytes := plainTAR(t, "a", []byte("payload"))
	inputs := []struct {
		name string
		data []byte
	}{
		{"archive.zip", plainZIP(t, "a", []byte("payload"))},
		{"archive.tar", tarBytes},
		{"archive.tgz", plainGZIP(t, tarBytes)},
	}
	for _, input := range inputs {
		path := writeFixture(t, dir, input.name, input.data)
		args := []string{"--format=json"}
		for _, algorithm := range algorithms {
			args = append(args, "--plain:"+algorithm)
		}
		got := invoke(t, append(args, path)...)
		if len(got) != len(algorithms) {
			t.Fatalf("%s: got %d records", input.name, len(got))
		}
		for i, algorithm := range algorithms {
			want := algorithm + ":" + hex.EncodeToString(sum(algorithm, input.data))
			if got[i].Scheme != "plain" || got[i].DigestAlgorithm != algorithm || got[i].Value != want {
				t.Errorf("%s/%s: got %#v, want plain value %q", input.name, algorithm, got[i], want)
			}
		}
	}

	path := writeFixture(t, dir, "commented.zip", inputs[0].data)
	got := invoke(t, "--plain", "--h1", "--format=json", path)
	if len(got) != 2 || got[1].Scheme != "plain" || got[1].Value != "sha256:"+hex.EncodeToString(sum("sha256", inputs[0].data)) {
		t.Fatalf("plain selection was not rendered last with exact archive bytes: %#v", got)
	}
	text := runOutput(t, "--plain", path)
	if want := "plain\tsha256:" + hex.EncodeToString(sum("sha256", inputs[0].data)) + "\t" + path + "\n"; text != want {
		t.Fatalf("got text %q, want %q", text, want)
	}
	text = runOutput(t, "--plain:sha1", path)
	if want := "plain:sha1\tsha1:" + hex.EncodeToString(sum("sha1", inputs[0].data)) + "\t" + path + "\n"; text != want {
		t.Fatalf("got override text %q, want %q", text, want)
	}
}

func runOutput(t *testing.T, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if status := run(args, &out, &errOut); status != 0 {
		t.Fatalf("status=%d stderr=%s", status, &errOut)
	}
	return out.String()
}

func TestPlainRejectsDirectoryAtomically(t *testing.T) {
	root := workspace(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	rejected(t, 3, "UNSUPPORTED_FORMAT", "--plain", "--h1", root)
	rejected(t, 3, "UNSUPPORTED_FORMAT", "--h1", "--plain", root)
}

func TestPlainNestedPayloadAndTreeInvariance(t *testing.T) {
	dir := workspace(t)
	inner := plainZIP(t, "a", []byte("inner"))
	outer := writeFixture(t, dir, "outer.zip", makeZIP(t, zip.Deflate, []string{"pkg/inner.zip"}, [][]byte{inner}))
	base := invoke(t, "--h1", "--plain", "--recurse", "--format=json", outer)
	excludedInnerFile := invoke(t, "--h1", "--plain", "--recurse", "--exclude=pkg/inner.zip!/a", "--format=json", outer)
	if len(base) != 4 || len(excludedInnerFile) != 4 {
		t.Fatalf("unexpected recursive records: %d / %d", len(base), len(excludedInnerFile))
	}
	if base[0].Value != excludedInnerFile[0].Value || base[1].Value != excludedInnerFile[1].Value ||
		base[3].Value != "sha256:"+hex.EncodeToString(sum("sha256", inner)) ||
		base[3].Value != excludedInnerFile[3].Value {
		t.Fatal("nested exclusions changed a parent or nested plain digest")
	}
	if base[2].Value == excludedInnerFile[2].Value {
		t.Fatal("nested exclusion did not affect the nested tree hash")
	}

	stripped := writeFixture(t, dir, "stripped.zip", makeZIP(t, zip.Deflate, []string{"pkg/inner.zip"}, [][]byte{inner}))
	strippedRecords := invoke(t, "--plain", "--recurse", "--strip-components=1", "--format=json", stripped)
	if len(strippedRecords) != 2 || strippedRecords[0].Value != "sha256:"+hex.EncodeToString(sum("sha256", readBytes(t, stripped))) ||
		strippedRecords[1].Value != base[3].Value {
		t.Fatal("prefix stripping changed an archive-byte digest")
	}

	wholeExcluded := invoke(t, "--plain", "--recurse", "--exclude=pkg/inner.zip", "--format=json", outer)
	if len(wholeExcluded) != 1 || wholeExcluded[0].Value != base[1].Value {
		t.Fatal("excluding a whole nested archive did not remove only its record")
	}

	innerTar := plainGZIP(t, plainTAR(t, "inside", []byte("gzip-payload")))
	outerTar := writeFixture(t, dir, "outer.tar", plainTAR(t, "pkg/inner.tgz", innerTar))
	tarRecords := invoke(t, "--plain", "--recurse", "--format=json", outerTar)
	if len(tarRecords) != 2 || tarRecords[1].InputType != "tar.gz" ||
		tarRecords[1].Value != "sha256:"+hex.EncodeToString(sum("sha256", innerTar)) {
		t.Fatalf("nested gzip archive digest mismatch: %#v", tarRecords)
	}
}

func TestPlainOnlyValidatesAndDoesNotDoubleCharge(t *testing.T) {
	dir := workspace(t)
	inner := plainZIP(t, "a", []byte("x"))
	outer := writeFixture(t, dir, "outer.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner}))
	limit := len(inner) + 1
	got := invoke(t, "--plain", "--recurse", fmt.Sprintf("--max-expanded-bytes=%d", limit), "--format=json", outer)
	if len(got) != 2 {
		t.Fatalf("exact expansion budget failed: %#v", got)
	}

	corrupt := append([]byte{}, makeZIP(t, zip.Store, []string{"a"}, [][]byte{[]byte("payload")})...)
	local := bytes.Index(corrupt, []byte("PK\x03\x04"))
	if local < 0 {
		t.Fatal("test ZIP has no local header")
	}
	nameLength := int(corrupt[local+26]) | int(corrupt[local+27])<<8
	extraLength := int(corrupt[local+28]) | int(corrupt[local+29])<<8
	corrupt[local+30+nameLength+extraLength] ^= 1
	path := writeFixture(t, dir, "corrupt.zip", corrupt)
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--plain", path)
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
