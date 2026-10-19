package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"
)

func legacySparseFixture(t *testing.T, stored []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	writer := tar.NewWriter(&result)
	if err := writer.WriteHeader(&tar.Header{Name: "a", Mode: 0644, Size: int64(len(stored)), Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(stored); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := result.Bytes()
	raw[156] = 'S'
	copy(raw[386:398], []byte("00000000003\x00"))
	copy(raw[398:410], []byte("00000000005\x00"))
	copy(raw[483:495], []byte("00000000012\x00"))
	for i := 148; i < 156; i++ {
		raw[i] = ' '
	}
	checksum := 0
	for _, b := range raw[:512] {
		checksum += int(b)
	}
	copy(raw[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	return raw
}

func TestSparseMapAccountsForEveryStoredByte(t *testing.T) {
	dir := workspace(t)
	valid := writeFixture(t, dir, "valid.tar", legacySparseFixture(t, []byte("ABCDE")))
	normal := writeFixture(t, dir, "normal.zip", makeZIP(t, 0, []string{"a"}, [][]byte{[]byte("\x00\x00\x00ABCDE\x00\x00")}))
	got := invoke(t, "--h1", "--nar", "--strict", "--format=json", valid)
	want := invoke(t, "--h1", "--nar", "--strict", "--format=json", normal)
	for i := range got {
		if got[i].Value != want[i].Value {
			t.Fatal("legacy sparse holes changed logical bytes")
		}
	}
	invalid := writeFixture(t, dir, "unclaimed.tar", legacySparseFixture(t, []byte("ABCDE!")))
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", invalid)
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", "--strict", invalid)
}
