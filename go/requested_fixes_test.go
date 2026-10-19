package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"testing"
)

func appendZIP16(b []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(b, encoded[:]...)
}

func appendZIP32(b []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(b, encoded[:]...)
}

func centralUnicodeASiZIP() []byte {
	rawName := []byte("caf\x82.txt")
	data := []byte("x")
	crc := crc32.ChecksumIEEE(data)

	asiBody := appendZIP16(nil, 0100644)
	asiBody = appendZIP32(asiBody, 0)
	asiBody = appendZIP16(asiBody, 0)
	asiBody = appendZIP16(asiBody, 0)
	asi := appendZIP16(nil, 0x756e)
	asi = appendZIP16(asi, uint16(4+len(asiBody)))
	asi = appendZIP32(asi, crc32.ChecksumIEEE(asiBody))
	asi = append(asi, asiBody...)

	unicodeBody := []byte{1}
	unicodeBody = appendZIP32(unicodeBody, crc32.ChecksumIEEE(rawName))
	unicodeBody = append(unicodeBody, []byte("coffee.txt")...)
	unicodePath := appendZIP16(nil, 0x7075)
	unicodePath = appendZIP16(unicodePath, uint16(len(unicodeBody)))
	unicodePath = append(unicodePath, unicodeBody...)

	local := appendZIP32(nil, 0x04034b50)
	local = appendZIP16(local, 20)
	local = appendZIP16(local, 0)
	local = appendZIP16(local, 0)
	local = appendZIP16(local, 0)
	local = appendZIP16(local, 0)
	local = appendZIP32(local, crc)
	local = appendZIP32(local, uint32(len(data)))
	local = appendZIP32(local, uint32(len(data)))
	local = appendZIP16(local, uint16(len(rawName)))
	local = appendZIP16(local, uint16(len(asi)))
	local = append(local, rawName...)
	local = append(local, asi...)
	local = append(local, data...)

	centralOffset := len(local)
	centralExtra := append(append([]byte{}, asi...), unicodePath...)
	central := appendZIP32(nil, 0x02014b50)
	central = appendZIP16(central, 3<<8|20)
	central = appendZIP16(central, 20)
	central = appendZIP16(central, 0)
	central = appendZIP16(central, 0)
	central = appendZIP16(central, 0)
	central = appendZIP16(central, 0)
	central = appendZIP32(central, crc)
	central = appendZIP32(central, uint32(len(data)))
	central = appendZIP32(central, uint32(len(data)))
	central = appendZIP16(central, uint16(len(rawName)))
	central = appendZIP16(central, uint16(len(centralExtra)))
	central = appendZIP16(central, 0)
	central = appendZIP16(central, 0)
	central = appendZIP16(central, 0)
	central = appendZIP32(central, 0)
	central = appendZIP32(central, 0)
	central = append(central, rawName...)
	central = append(central, centralExtra...)

	result := append(local, central...)
	result = appendZIP32(result, 0x06054b50)
	result = appendZIP16(result, 0)
	result = appendZIP16(result, 0)
	result = appendZIP16(result, 1)
	result = appendZIP16(result, 1)
	result = appendZIP32(result, uint32(len(central)))
	result = appendZIP32(result, uint32(centralOffset))
	result = appendZIP16(result, 0)
	return result
}

func tarWithEntry(name string, data []byte) []byte {
	header := make([]byte, 512)
	copy(header, name)
	copy(header[100:108], fmt.Sprintf("%07o\x00", 0644))
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", len(data)))
	copy(header[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	header[156] = '0'
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	var checksum int
	for _, value := range header {
		checksum += int(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	result := append(header, data...)
	if padding := len(data) % 512; padding != 0 {
		result = append(result, make([]byte, 512-padding)...)
	}
	return append(result, make([]byte, 1024)...)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	w := gzip.NewWriter(&result)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestDriveQualifiedRootAfterLeadingDot(t *testing.T) {
	dir := workspace(t)
	tests := []struct {
		fileName, entryName string
		options             []string
	}{
		{"drive.zip", "C:x", nil},
		{"dot-drive.zip", "./C:x", nil},
		{"absolute-drive.zip", "/C:x", nil},
		{"projected-drive.zip", "pkg/C:x", []string{"--strip-components=1"}},
	}
	for _, test := range tests {
		path := writeFixture(t, dir, test.fileName, makeZIP(t, 0, []string{test.entryName}, [][]byte{[]byte("x")}))
		for _, strict := range []bool{false, true} {
			args := []string{"--h1", "--format=json"}
			args = append(args, test.options...)
			if strict {
				args = append(args, "--strict")
			}
			rejected(t, 1, "INVALID_PATH", append(args, path)...)
		}
	}
}

func TestValidTARMagicNameWinsOverZIPSniff(t *testing.T) {
	dir := workspace(t)
	name := string([]byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0, 'e', 'v', 'i', 'l'})
	path := writeFixture(t, dir, "pk-name.tar", tarWithEntry(name, []byte("x")))
	got := invoke(t, "--h1", "--format=json", path)
	if got[0].InputType != "tar" {
		t.Fatalf("ZIP-like TAR filename was classified as %q", got[0].InputType)
	}
}

func TestZIPDetectionDoesNotCapVersionNeeded(t *testing.T) {
	dir := workspace(t)
	data := makeZIP(t, 0, []string{"a"}, [][]byte{[]byte("x")})
	binary.LittleEndian.PutUint16(data[4:6], 99)
	central := bytes.Index(data, []byte("PK\x01\x02"))
	if central < 0 {
		t.Fatal("ZIP central header not found")
	}
	binary.LittleEndian.PutUint16(data[central+6:central+8], 99)
	path := writeFixture(t, dir, "future-version.zip", data)
	if got := invoke(t, "--h1", "--format=json", path); len(got) != 1 || got[0].InputType != "zip" {
		t.Fatalf("version-needed header was not recognized as ZIP: %#v", got)
	}
}

func TestNestedZIPRejectsTrailingBytesInAllModes(t *testing.T) {
	dir := workspace(t)
	zipBytes := append(makeZIP(t, 0, []string{"a"}, [][]byte{[]byte("x")}), []byte("junk")...)
	direct := writeFixture(t, dir, "direct-trailing.zip", zipBytes)
	path := writeFixture(t, dir, "nested-trailing.tar", tarWithEntry("nested.zip", zipBytes))
	for _, strict := range []bool{false, true} {
		args := []string{"--h1", "--recurse", "--format=json"}
		if strict {
			args = append(args, "--strict")
		}
		rejected(t, 1, "ARCHIVE_LAYOUT", append(append([]string{}, args...), direct)...)
		rejected(t, 1, "ARCHIVE_LAYOUT", append(args, path)...)
	}
}

func TestStreamedCentralUnicodeNameWithLocalASiDoesNotHashWrongName(t *testing.T) {
	dir := workspace(t)
	nested := centralUnicodeASiZIP()
	direct := writeFixture(t, dir, "direct.zip", nested)

	flags := []string{"--h1", "--h1-go", "--gittree", "--swhid", "--nar", "--format=json"}
	top := invoke(t, append(flags, direct)...)
	seekableOuter := writeFixture(t, dir, "seekable-outer.tar", tarWithEntry("nested.zip", nested))
	seekable := invoke(t, append(append([]string{}, flags...), "--recurse", seekableOuter)...)
	if len(seekable) != 2*len(top) {
		t.Fatalf("unexpected seekable nested result count: %d", len(seekable))
	}
	for i := range top {
		if seekable[len(top)+i].Value != top[i].Value {
			t.Fatalf("seekable nested %s hash disagrees with top-level ZIP", top[i].Scheme)
		}
	}

	outer := writeFixture(t, dir, "streamed-outer.tgz", gzipBytes(t, tarWithEntry("nested.zip", nested)))
	args := append(append([]string{}, flags...), "--recurse", outer)
	spooled := invoke(t, args...)
	for i := range top {
		if spooled[len(top)+i].Value != top[i].Value {
			t.Fatalf("spooled nested %s hash disagrees with top-level ZIP", top[i].Scheme)
		}
	}
	// The seekable top-level path uses the authoritative central name.
	if len(top) != len(flags)-1 {
		t.Fatalf("unexpected direct result count: %d", len(top))
	}
}
