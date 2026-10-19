package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func zip64End(t *testing.T, sentinel bool, extension []byte) []byte {
	t.Helper()
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("A")})
	end := append([]byte{}, raw[len(raw)-22:]...)
	offset := len(raw) - 22
	record := make([]byte, 56)
	binary.LittleEndian.PutUint32(record, 0x06064b50)
	binary.LittleEndian.PutUint64(record[4:], uint64(44+len(extension)))
	binary.LittleEndian.PutUint16(record[12:], 45)
	binary.LittleEndian.PutUint16(record[14:], 45)
	binary.LittleEndian.PutUint64(record[24:], 1)
	binary.LittleEndian.PutUint64(record[32:], 1)
	binary.LittleEndian.PutUint64(record[40:], uint64(u32(end[12:])))
	binary.LittleEndian.PutUint64(record[48:], uint64(u32(end[16:])))
	locator := make([]byte, 20)
	binary.LittleEndian.PutUint32(locator, 0x07064b50)
	binary.LittleEndian.PutUint64(locator[8:], uint64(offset))
	binary.LittleEndian.PutUint32(locator[16:], 1)
	if sentinel {
		for i := 8; i < 20; i++ {
			end[i] = 0xff
		}
	}
	result := append([]byte{}, raw[:offset]...)
	result = append(result, record...)
	result = append(result, extension...)
	result = append(result, locator...)
	return append(result, end...)
}

func nestedZIPGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	gz := gzip.NewWriter(&result)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "nested.zip", Mode: 0644, Size: int64(len(raw))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestZIP64EndRecordVariants(t *testing.T) {
	dir := workspace(t)
	for _, sentinel := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary-eocd", true: "sentinel-eocd"}[sentinel], func(t *testing.T) {
			// APPNOTE extensible data sector: two-byte ID and four-byte length.
			extra := []byte{0x65, 0, 25, 0, 0, 0, 0xe9, 0xf3, 0xf9, 0xf0,
				0, 5, 0, 0x71, 0,
				0, 5, 0, 0x72, 0,
				0, 5, 0, 0x73, 0,
				0, 6, 0, 0x74, 0, 0}
			raw := zip64End(t, sentinel, extra)
			path := writeFixture(t, dir, "extended.zip", raw)
			_ = invoke(t, "--h1", "--strict", "--format=json", path)
			path = writeFixture(t, dir, "nested.tgz", nestedZIPGzip(t, raw))
			_ = invoke(t, "--h1", "--strict", "--recurse", "--format=json", path)
		})
	}
}

func TestStreamingZIP64LocatorOffset(t *testing.T) {
	raw := zip64End(t, true, nil)
	binary.LittleEndian.PutUint64(raw[len(raw)-34:], 1)
	path := writeFixture(t, workspace(t), "bad-locator.tgz", nestedZIPGzip(t, raw))
	rejected(t, 1, "ARCHIVE_LAYOUT", "--h1", "--strict", path)
}

func TestStreamingZIPDeferredLocalCRC(t *testing.T) {
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("A")})
	binary.LittleEndian.PutUint32(raw[14:], 1)
	path := writeFixture(t, workspace(t), "bad-placeholder.tgz", nestedZIPGzip(t, raw))
	rejected(t, 1, "ARCHIVE_LAYOUT", "--h1", "--strict", path)
}

func TestStreamingZIP64SentinelsRequireEndChain(t *testing.T) {
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("A")})
	for i := len(raw) - 14; i < len(raw)-2; i++ {
		raw[i] = 0xff
	}
	path := writeFixture(t, workspace(t), "missing-zip64.tgz", nestedZIPGzip(t, raw))
	rejected(t, 1, "ARCHIVE_LAYOUT", "--h1", "--strict", path)
}

func TestZIP64UnknownExtensibleSector(t *testing.T) {
	raw := zip64End(t, true, []byte{0xfe, 0xca, 3, 0, 0, 0, 'x', 'y', 'z'})
	path := writeFixture(t, workspace(t), "unsupported.zip", raw)
	rejected(t, 3, "UNSUPPORTED_FORMAT", "--h1", "--strict", path)
	path = writeFixture(t, workspace(t), "unsupported.tgz", nestedZIPGzip(t, raw))
	rejected(t, 3, "UNSUPPORTED_FORMAT", "--h1", "--strict", path)
}

func TestZIPCommentContainsEndSignature(t *testing.T) {
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("A")})
	binary.LittleEndian.PutUint16(raw[len(raw)-2:], 22)
	comment := make([]byte, 22)
	binary.LittleEndian.PutUint32(comment, 0x06054b50)
	raw = append(raw, comment...)
	dir := workspace(t)
	path := writeFixture(t, dir, "comment.zip", raw)
	_ = invoke(t, "--h1", "--nar", "--strict", "--format=json", path)
	path = writeFixture(t, dir, "nested.tgz", nestedZIPGzip(t, raw))
	_ = invoke(t, "--h1", "--nar", "--strict", "--recurse", "--format=json", path)
}

func TestZIPUnsignedDescriptorSignatureCRC(t *testing.T) {
	payload := []byte{0xac, 0x0a, 0x7a, 0xd5}
	if crc32.ChecksumIEEE(payload) != 0x08074b50 {
		t.Fatal("invalid shared descriptor-signature CRC fixture")
	}
	raw := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{payload})
	end := len(raw) - 22
	central := int(u32(raw[end+16:]))
	descriptor := central - 16
	if u32(raw[descriptor:]) != 0x08074b50 || u32(raw[descriptor+4:]) != 0x08074b50 {
		t.Fatal("unexpected fixture descriptor")
	}

	raw = append(raw[:descriptor], raw[descriptor+4:]...)
	binary.LittleEndian.PutUint32(raw[len(raw)-6:], uint32(central-4))
	dir := workspace(t)
	path := writeFixture(t, dir, "unsigned.zip", raw)
	_ = invoke(t, "--h1", "--strict", "--format=json", path)
	_ = invoke(t, "--nar", "--strict", "--format=json", path)
	path = writeFixture(t, dir, "nested.tgz", nestedZIPGzip(t, raw))
	_ = invoke(t, "--h1", "--strict", "--recurse", "--format=json", path)
}

func TestDeferredStreamingCodecs(t *testing.T) {
	data := []byte("bounded bzip2 stream")
	bzip, err := hex.DecodeString("425a68393141592653591eb2775e0000021980400010003623de102000228c9a3087ea8530004d3293a7648ad90570906f8bb9229c28480f593baf00")
	if err != nil {
		t.Fatal(err)
	}
	var xzData bytes.Buffer
	xw, err := xz.NewWriter(&xzData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = xw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = xw.Close(); err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	zstdData := encoder.EncodeAll(data, nil)
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	for method, compressed := range map[uint16][]byte{12: bzip, 20: zstdData, 93: zstdData, 95: xzData.Bytes()} {
		t.Run(map[uint16]string{12: "bzip2", 20: "zstd20", 93: "zstd93", 95: "xz"}[method], func(t *testing.T) {
			var result bytes.Buffer
			zw := zip.NewWriter(&result)
			h := &zip.FileHeader{Name: "a", ReaderVersion: 63, Flags: 8, Method: method, CRC32: crc32.ChecksumIEEE(data), CompressedSize64: uint64(len(compressed)), UncompressedSize64: uint64(len(data))}
			w, err := zw.CreateRaw(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write(compressed); err != nil {
				t.Fatal(err)
			}
			if err = zw.Close(); err != nil {
				t.Fatal(err)
			}
			raw := result.Bytes()
			for i := 14; i < 26; i++ {
				raw[i] = 0
			}
			dir := workspace(t)
			root := writeFixture(t, dir, "original.zip", raw)
			expected := invoke(t, "--h1", "--nar", "--strict", "--format=json", root)
			path := writeFixture(t, dir, "nested.tgz", nestedZIPGzip(t, raw))
			actual := invoke(t, "--h1", "--nar", "--strict", "--recurse", "--format=json", path)
			for i := range expected {
				if actual[i+len(expected)].Value != expected[i].Value {
					t.Fatal("deferred streaming codec changed nested content")
				}
			}
		})
	}
}
