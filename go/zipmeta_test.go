package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	godirhash "golang.org/x/mod/sumdb/dirhash"
)

func asiExtra(mode uint16, target []byte) []byte {
	body := make([]byte, 10)
	binary.LittleEndian.PutUint16(body, mode)
	if mode&0170000 == 0120000 {
		binary.LittleEndian.PutUint32(body[2:], uint32(len(target)))
	}
	body = append(body, target...)
	field := make([]byte, 8)
	binary.LittleEndian.PutUint16(field, 0x756e)
	binary.LittleEndian.PutUint16(field[2:], uint16(4+len(body)))
	binary.LittleEndian.PutUint32(field[4:], crc32.ChecksumIEEE(body))
	return append(field, body...)
}
func TestASIModesTargetsAndGoManifest(t *testing.T) {
	dir := workspace(t)
	build := func(legacy bool) []byte {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		h := &zip.FileHeader{Name: "a", Method: zip.Store}
		h.SetMode(0755)
		if legacy {
			h.CreatorVersion = 20
			h.ExternalAttrs = 0
			h.Extra = asiExtra(0100755, nil)
		}
		file, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.Write([]byte("A"))
		link := &zip.FileHeader{Name: "link", Method: zip.Store}
		link.SetMode(os.ModeSymlink | 0777)
		if legacy {
			link.CreatorVersion = 20
			link.ExternalAttrs = 0
			link.Extra = asiExtra(0120777, []byte("a"))
		}
		file, err = w.CreateHeader(link)
		if err != nil {
			t.Fatal(err)
		}
		if !legacy {
			_, _ = file.Write([]byte("a"))
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	legacy := writeFixture(t, dir, "asi.zip", build(true))
	modern := writeFixture(t, dir, "unix.zip", build(false))
	flags := []string{"--h1", "--h1-go", "--gittree", "--swhid", "--nar", "--strict", "--format=json"}
	got := invoke(t, append(flags, legacy)...)
	want := invoke(t, append(flags, modern)...)
	for i := range got {
		if got[i].Scheme != "h1-go" && got[i].Value != want[i].Value {
			t.Errorf("ASi metadata changed %s", got[i].Scheme)
		}
	}
	oracle, err := godirhash.HashZip(legacy, godirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	if got[1].Value != oracle {
		t.Fatal("Go manifest used extra-field target rather than stored payload")
	}
	_ = invoke(t, "--h1", "--max-expanded-bytes=2", "--format=json", legacy)
	rejected(t, 1, "LIMIT_EXCEEDED", "--h1", "--max-expanded-bytes=1", legacy)
	bad := asiExtra(0100644, nil)
	bad[len(bad)-1] ^= 1
	if _, err := parseASI(bad); err == nil {
		t.Fatal("ASi CRC ignored")
	}
}
func TestSemanticZIPExtraReconciliation(t *testing.T) {
	if err := reconcileZIPExtras(asiExtra(0100644, nil), asiExtra(0100755, nil)); err == nil {
		t.Fatal("contradictory Unix permissions accepted")
	}
	ut := func(flags byte, values ...uint32) []byte {
		b := []byte{0x55, 0x54, byte(1 + 4*len(values)), 0, flags}
		for _, n := range values {
			b = binary.LittleEndian.AppendUint32(b, n)
		}
		return b
	}
	if err := reconcileZIPExtras(ut(7, 1, 2, 3), ut(7, 1)); err != nil {
		t.Fatal("legal timestamp placement rejected", err)
	}
	if err := reconcileZIPExtras(ut(1, 1), ut(1, 2)); err == nil {
		t.Fatal("mtime conflict accepted")
	}
	unix3 := func(uid []byte) []byte {
		payload := append([]byte{1, byte(len(uid))}, uid...)
		payload = append(payload, 1, 2)
		return append([]byte{0x75, 0x78, byte(len(payload)), 0}, payload...)
	}
	if err := reconcileZIPExtras(unix3([]byte{1}), unix3([]byte{1, 0})); err != nil {
		t.Fatal("equivalent variable-width UID rejected", err)
	}
	if err := reconcileZIPExtras(unix3([]byte{1}), unix3([]byte{3})); err == nil {
		t.Fatal("UID conflict accepted")
	}
}
func TestSeekableFilesystemZIPPreflight(t *testing.T) {
	dir := workspace(t)
	source := writeFixture(t, dir, "inner.zip", makeZIP(t, zip.Store, []string{"a"}, [][]byte{[]byte("A")}))
	direct := invoke(t, "--gittree", "--format=json", source)
	plain := invoke(t, "--gittree", "--format=json", dir)
	nested := invoke(t, "--gittree", "--strict", "--recurse", "--format=json", dir)
	if len(nested) != 2 || nested[0].Value != plain[0].Value || nested[1].Value != direct[0].Value {
		t.Fatal("seekable nested ZIP did not use available central metadata")
	}
	if nested[1].ArchiveEntries[0] != filepath.Base(source) {
		t.Fatal("nested identity changed")
	}
	nar := invoke(t, "--nar", "--strict", "--recurse", "--format=json", dir)
	narDirect := invoke(t, "--nar", "--format=json", source)
	if len(nar) != 2 || nar[1].Value != narDirect[0].Value {
		t.Fatal("NAR reread ignored preflight sizes")
	}
}
