package main

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestGzipDiscoveryRequiresTARContent(t *testing.T) {
	dir := workspace(t)
	var js bytes.Buffer
	gzw := gzip.NewWriter(&js)
	if _, err := gzw.Write(bytes.Repeat([]byte("javascript source;"), 600)); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	jarBytes := makeZIP(t, 8, []string{"VAADIN/vaadinBootstrap.js.gz"}, [][]byte{js.Bytes()})
	jar := writeFixture(t, dir, "frontend.jar", jarBytes)

	for _, strict := range []bool{false, true} {
		args := []string{"--h1", "--plain", "--recurse", "--format=json"}
		if strict {
			args = append(args, "--strict")
		}
		records := invoke(t, append(args, jar)...)
		if len(records) != 2 || records[0].InputType != "zip" || records[1].Scheme != "plain" {
			t.Fatalf("ordinary gzip member was treated as TAR.GZ (strict=%v): %#v", strict, records)
		}
	}

	extensionless := plainGZIP(t, plainTAR(t, "inside", []byte("payload")))
	outerBytes := makeZIP(t, 8, []string{"payload.data"}, [][]byte{extensionless})
	outer := writeFixture(t, dir, "extensionless.zip", outerBytes)
	records := invoke(t, "--h1", "--plain", "--recurse", "--strict", "--format=json", outer)
	if len(records) != 4 || records[2].InputType != "tar.gz" || records[3].ArchiveEntries[len(records[3].ArchiveEntries)-1] != "payload.data" {
		t.Fatalf("extensionless TAR.GZ was not recursively identified: %#v", records)
	}

	badTAR := plainTAR(t, "not-tar", []byte("payload"))
	badTAR[148] ^= 1
	opaque := writeFixture(t, dir, "opaque-invalid-header.zip", makeZIP(t, 8, []string{"payload.data"}, [][]byte{badTAR}))
	for _, strict := range []bool{false, true} {
		args := []string{"--h1", "--recurse", "--format=json"}
		if strict {
			args = append(args, "--strict")
		}
		if got := invoke(t, append(args, opaque)...); len(got) != 1 {
			t.Fatalf("invalid TAR checksum in ordinary member was not opaque: %#v", got)
		}
	}
	explicit := writeFixture(t, dir, "bad-header.tar", badTAR)
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", explicit)

	invalid := writeFixture(t, dir, "broken.tgz", []byte{0x1f, 0x8b, 0x08, 0, 1, 2, 3})
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", invalid)
	rootGzip := writeFixture(t, dir, "bootstrap.js.gz", js.Bytes())
	rejected(t, 3, "UNSUPPORTED_FORMAT", "--h1", rootGzip)

	badTrailer := append([]byte{}, extensionless...)
	badTrailer[len(badTrailer)-8] ^= 1
	truncated := writeFixture(t, dir, "bad-trailer.tgz", badTrailer)
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", truncated)
}
