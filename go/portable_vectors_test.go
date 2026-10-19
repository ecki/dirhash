package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestPortableCP437StripManifest(t *testing.T) {
	dir := workspace(t)
	original := writeFixture(t, dir, "cp437.zip", makeZIP(t, zip.Store, []string{"pkg/\x82"}, [][]byte{[]byte("A")}))
	transformed := writeFixture(t, dir, "projected.zip", makeZIP(t, zip.Store, []string{"\x82"}, [][]byte{[]byte("A")}))
	got := invoke(t, "--h1", "--h1-go", "--strip-components=1", "--format=json", original)
	want := invoke(t, "--h1", "--h1-go", "--format=json", transformed)
	for i := range got {
		if got[i].Value != want[i].Value {
			t.Fatal("prefix stripping changed the raw CP437 compatibility name")
		}
	}
	if got[0].Value == got[1].Value {
		t.Fatal("common UTF-8 manifest used raw CP437 name")
	}
}

func TestPortablePKWARELinkMetadata(t *testing.T) {
	dir := workspace(t)
	makeArchive := func(extraTarget bool) []byte {
		var result bytes.Buffer
		writer := zip.NewWriter(&result)
		for _, name := range []string{"a", "link"} {
			header := &zip.FileHeader{Name: name, Method: zip.Store}
			data := []byte("A")
			header.SetMode(0644)
			if name == "link" {
				header.SetMode(os.ModeSymlink | 0777)
				data = []byte("a")
				if extraTarget {
					header.Extra = []byte{0x0d, 0, 13, 0}
					header.Extra = append(header.Extra, make([]byte, 12)...)
					header.Extra = append(header.Extra, 'a')
					data = nil
				}
			}
			out, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = out.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return result.Bytes()
	}
	modern := writeFixture(t, dir, "modern.zip", makeArchive(false))
	legacy := writeFixture(t, dir, "pkware.zip", makeArchive(true))
	flags := []string{"--h1", "--h1-go", "--gittree", "--swhid", "--nar", "--strict", "--format=json"}
	want := invoke(t, append(flags, modern)...)
	got := invoke(t, append(flags, legacy)...)
	for i := range got {
		if (got[i].Value == want[i].Value) == (got[i].Scheme == "h1-go") {
			t.Fatalf("incorrect PKWARE common/manifest view for %s", got[i].Scheme)
		}
	}
}

func TestPortableNTFSConflictingAttributes(t *testing.T) {
	field := make([]byte, 4)
	for _, stamp := range []uint64{1, 2} {
		body := make([]byte, 28)
		binary.LittleEndian.PutUint16(body, 1)
		binary.LittleEndian.PutUint16(body[2:], 24)
		binary.LittleEndian.PutUint64(body[4:], stamp)
		field = append(field, body...)
	}
	if _, err := ntfsTimes(field); err == nil {
		t.Fatal("duplicate contradictory NTFS timestamps accepted")
	}
}

func TestPortableShortMagicIsOpaque(t *testing.T) {
	for _, content := range [][]byte{{'P', 'K', 3, 4}, {31, 139, 8}, []byte("ustar")} {
		dir := workspace(t)
		_ = writeFixture(t, dir, "opaque.bin", content)
		got := invoke(t, "--h1", "--strict", "--recurse", "--format=json", dir)
		if len(got) != 1 {
			t.Fatal("short magic bytes were classified as a complete archive")
		}
	}
}
