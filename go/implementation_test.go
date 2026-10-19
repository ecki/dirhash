package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	godirhash "golang.org/x/mod/sumdb/dirhash"
)

func workspace(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp(".", ".dirhash-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(p) })
	return p
}
func invoke(t *testing.T, args ...string) []record {
	t.Helper()
	var out, errOut bytes.Buffer
	if status := run(args, &out, &errOut); status != 0 {
		t.Fatalf("status=%d stderr=%s", status, &errOut)
	}
	var response struct {
		SchemaVersion int
		Results       []record
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != 1 {
		t.Fatal("schema version")
	}
	return response.Results
}
func rejected(t *testing.T, status int, code string, args ...string) {
	t.Helper()
	var out, errOut bytes.Buffer
	actual := run(args, &out, &errOut)
	if actual != status || out.Len() != 0 || !strings.HasPrefix(errOut.String(), code) {
		t.Fatalf("got %d stdout=%q stderr=%q", actual, &out, &errOut)
	}
}
func TestPrimitiveVectors(t *testing.T) {
	vectors := map[string]string{
		"sha1":        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha512":      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"blake2b-256": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		"blake2b-512": "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		"blake3":      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		"sha3-256":    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"sha3-512":    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
	}
	for a, want := range vectors {
		if got := hex.EncodeToString(sum(a, nil)); got != want {
			t.Errorf("%s: %s", a, got)
		}
	}
}
func TestSWHPreservesEmptyDirectories(t *testing.T) {
	root := workspace(t)
	if err := os.MkdirAll(filepath.Join(root, "outer", "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			got := invoke(t, "--gittree:"+algorithm, "--swhid:"+algorithm, "--format=json", root)
			leaf := object(algorithm, "tree", nil)
			outer := object(algorithm, "tree", append([]byte("40000 empty\x00"), leaf...))
			want := object(algorithm, "tree", append([]byte("40000 outer\x00"), outer...))
			if got[0].Value != render(selection{"gittree", algorithm}, leaf) {
				t.Fatal("Git did not omit empty subdirectories")
			}
			if got[1].Value != render(selection{"swhid", algorithm}, want) {
				t.Fatal("Software Heritage omitted an empty subdirectory")
			}
		})
	}
}
func TestUnicode16Validation(t *testing.T) {
	for _, pair := range [][2]string{{"Straße", "STRASSE"}, {"ς", "Σ"}, {"é", "e\u0301"}, {"\u1c89", "\u1c8a"}} {
		if unicode16Fold(pair[0]) != unicode16Fold(pair[1]) {
			t.Errorf("fold mismatch %q %q", pair[0], pair[1])
		}
	}
	for _, s := range []string{"a\u200db", "\u0001", "NUL.txt", "COM¹.foo", "conout$", "bad.", "bad ", "\ufdd0", "\U0001ffff"} {
		if portableComponent(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if nfc16("\u1100\u1161\u11a8") != "각" {
		t.Error("Hangul composition")
	}
}
func TestPatterns(t *testing.T) {
	tests := []struct {
		p         string
		chain     []string
		name      string
		dir, want bool
	}{
		{"*.tmp", nil, "dir/a.tmp", false, false},
		{"**/*.tmp", nil, "dir/a.tmp", false, true},
		{"dir/", nil, "dir/a", false, true},
		{"outer.zip!/**/*.tmp", []string{"outer.zip"}, "lib/a.tmp", false, true},
		{"outer.zip!/**/*.tmp", []string{"other.zip"}, "a.tmp", false, false},
		{"a!!b.zip!/x", []string{"a!b.zip"}, "x", false, true},
		{"**/x", []string{"outer.zip"}, "x", false, false},
	}
	for _, tt := range tests {
		p, err := compilePattern(tt.p)
		if err != nil {
			t.Fatal(err)
		}
		o := options{excludes: []pattern{p}}
		if got := o.excluded(tt.chain, tt.name, tt.dir); got != tt.want {
			t.Errorf("%s got %v", tt.p, got)
		}
	}
	for _, p := range []string{"", "/x", "a//b", "a!b", "a!/", "a/**x"} {
		if _, err := compilePattern(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
}
func makeZIP(t *testing.T, method uint16, names []string, contents [][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i, name := range names {
		h := &zip.FileHeader{Name: name, Method: method}
		h.SetMode(0644)
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(contents[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func writeFixture(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestGoHashOraclesAndDirectoryMarkers(t *testing.T) {
	dir := workspace(t)
	root := filepath.Join(dir, "tree")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(root, "lib"), 0700)
	_ = os.WriteFile(filepath.Join(root, "lib", "a"), []byte("hello"), 0600)
	want, err := godirhash.HashDir(root, "", godirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	got := invoke(t, "--h1-go", "--format=json", root)
	if got[0].Value != want {
		t.Fatalf("HashDir %s != %s", got[0].Value, want)
	}
	z := makeZIP(t, zip.Deflate, []string{"module@v1/", "module@v1/a"}, [][]byte{nil, []byte("hello")})
	p := writeFixture(t, dir, "module.zip", z)
	want, err = godirhash.HashZip(p, godirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	got = invoke(t, "--h1-go", "--strict", "--format=json", p)
	if got[0].Value != want {
		t.Fatalf("HashZip %s != %s", got[0].Value, want)
	}
}
func TestDirectoryArchiveEquivalence(t *testing.T) {
	dir := workspace(t)
	root := filepath.Join(dir, "tree")
	_ = os.Mkdir(root, 0700)
	_ = os.Mkdir(filepath.Join(root, "empty"), 0700)
	_ = os.WriteFile(filepath.Join(root, "a"), []byte("hello"), 0644)
	z := writeFixture(t, dir, "input.zip", makeZIP(t, zip.Deflate, []string{"a", "empty/"}, [][]byte{[]byte("hello"), nil}))
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for _, h := range []*tar.Header{{Name: "a", Mode: 0644, Size: 5}, {Name: "empty/", Mode: 0755, Typeflag: tar.TypeDir}} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write([]byte("hello"))
		}
	}
	_ = tw.Close()
	tarPath := writeFixture(t, dir, "input.tar", tb.Bytes())
	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	_, _ = gw.Write(tb.Bytes())
	_ = gw.Close()
	gzPath := writeFixture(t, dir, "input.tgz", gb.Bytes())
	flags := []string{"--h1", "--gittree", "--gittree:sha256", "--swhid", "--nar", "--strict", "--format=json"}
	want := invoke(t, append(flags, root)...)
	for _, p := range []string{z, tarPath, gzPath} {
		got := invoke(t, append(flags, p)...)
		for i := range got {
			if got[i].Value != want[i].Value {
				t.Errorf("%s %s", p, got[i].Scheme)
			}
		}
	}
}
func TestAtomicArchiveFailures(t *testing.T) {
	dir := workspace(t)
	z := makeZIP(t, zip.Store, []string{"a"}, [][]byte{[]byte("hello")})
	p := writeFixture(t, dir, "valid.zip", z)
	_ = invoke(t, "--h1", "--strict", "--format=json", p)
	junk := writeFixture(t, dir, "junk.zip", append(append([]byte{}, z...), 1))
	rejected(t, 1, "ARCHIVE_LAYOUT", "--h1", "--strict", junk)
	corrupt := append([]byte{}, z...)
	offset := bytes.Index(corrupt, []byte("hello"))
	corrupt[offset] ^= 1
	rejected(t, 1, "ARCHIVE_INTEGRITY", "--h1", writeFixture(t, dir, "crc.zip", corrupt))
	duplicate := makeZIP(t, zip.Store, []string{"a", "./a"}, [][]byte{nil, nil})
	rejected(t, 1, "DUPLICATE_ENTRY", "--h1", writeFixture(t, dir, "duplicate.zip", duplicate))
	bad := makeZIP(t, zip.Store, []string{"bad\\name"}, [][]byte{nil})
	rejected(t, 1, "INVALID_PATH", "--h1", "--exclude=**", writeFixture(t, dir, "bad.zip", bad))
}
func TestNestedStreamingAndParentInvariance(t *testing.T) {
	dir := workspace(t)
	inner := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("payload")})
	outer := makeZIP(t, zip.Store, []string{"inner.zip"}, [][]byte{inner})
	p := writeFixture(t, dir, "outer.zip", outer)
	root := invoke(t, "--h1", "--format=json", p)
	nested := invoke(t, "--h1", "--recurse", "--format=json", p)
	if len(nested) != 2 || nested[0].Value != root[0].Value || nested[1].ArchiveEntries[0] != "inner.zip" {
		t.Fatal("recursion changed parent")
	}
	_ = invoke(t, "--gittree", "--recurse", "--format=json", p)
	compressed := writeFixture(t, dir, "compressed.zip", makeZIP(t, zip.Deflate, []string{"inner.zip"}, [][]byte{inner}))
	_ = invoke(t, "--gittree", "--swhid", "--recurse", "--format=json", compressed)
	_ = invoke(t, "--gittree", "--strict", "--format=json", p)
	nar := invoke(t, "--nar", "--recurse", "--format=json", p)
	if len(nar) != 2 {
		t.Fatal("NAR-only nested reread failed")
	}
}
func TestAdoptedZIPCodecDecoders(t *testing.T) {
	data := bytes.Repeat([]byte("a pure Go codec fixture\n"), 100)
	for _, method := range []uint16{20, 93, 95} {
		var compressed bytes.Buffer
		if method == 95 {
			w, err := xz.NewWriter(&compressed)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(data)
			_ = w.Close()
		} else {
			w, err := zstd.NewWriter(&compressed)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(data)
			_ = w.Close()
		}
		r, err := zipCodec(method, bytes.NewReader(compressed.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("method %d: %v", method, err)
		}
	}
	for _, method := range []uint16{9, 14, 98} {
		if _, err := zipCodec(method, bytes.NewReader(nil)); err == nil {
			t.Errorf("unsupported method %d", method)
		}
	}
}

type onceReader struct {
	r io.Reader
	n *int
}

func (r onceReader) Read(b []byte) (int, error) { n, e := r.r.Read(b); *r.n += n; return n, e }
func TestSingleReadDigestFanout(t *testing.T) {
	o, err := parse([]string{"--h1", "--h1:sha512", "--gittree", "--gittree:sha256", "--swhid", "input"})
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(o)
	n, _ := e.newNamespace(nil, "tar", nil, 0, true)
	data := bytes.Repeat([]byte("x"), 300000)
	read := 0
	ent, err := n.add("a", 'f', 0644, int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.payload(n, ent, onceReader{bytes.NewReader(data), &read}, true, false); err != nil {
		t.Fatal(err)
	}
	if read != len(data) || len(ent.raw) != 2 || len(ent.blob) != 2 {
		t.Fatal("payload fanout reread or omitted consumer")
	}
	for a, v := range ent.raw {
		if !bytes.Equal(v, sum(a, data)) {
			t.Fatal(a)
		}
	}
	for a, v := range ent.blob {
		if !bytes.Equal(v, object(a, "blob", data)) {
			t.Fatal(a)
		}
	}
}
func TestSelectionsAndStableRendering(t *testing.T) {
	dir := workspace(t)
	args := []string{"--format=json"}
	for _, s := range schemes {
		for _, a := range algorithms {
			args = append(args, fmt.Sprintf("--%s:%s", s, a))
		}

	}
	input := writeFixture(t, dir, "empty.zip", makeZIP(t, zip.Store, nil, nil))
	args = append(args, input)
	records := invoke(t, args...)
	if len(records) != 48 {
		t.Fatal(len(records))
	}
	for i, r := range records {
		if r.Scheme != schemes[i/8] || r.DigestAlgorithm != algorithms[i%8] {
			t.Fatal("unstable order")
		}
	}
	rejected(t, 2, "USAGE_ERROR", "--h1", "--format=json", "--format=text", dir)
	rejected(t, 2, "USAGE_ERROR", "--h1:sha3", dir)
	rejected(t, 1, "LIMIT_EXCEEDED", "--h1", "--max-entries=0", writeFixture(t, dir, "one.zip", makeZIP(t, zip.Store, []string{"a"}, [][]byte{nil})))
}

func TestExactJSONUnicodeAndEscapes(t *testing.T) {
	s := "literal\\u2028 actual\u2028 and\u2029 <>& \x01\n\t"
	encoded := jsonString(s)
	if strings.Contains(encoded, `actual\u2028`) {
		t.Fatal("non-ASCII scalar was escaped")
	}
	var decoded string
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil || decoded != s {
		t.Fatalf("%q: %v", encoded, err)
	}
	if !strings.Contains(encoded, `\u0001\n\t`) {
		t.Fatal(encoded)
	}
	f := fail("INVALID_PATH", "name\x1b[31m\u202e", "reason\ninjection").Error()
	if strings.ContainsAny(f, "\x1b\n\u202e") {
		t.Fatal("unsafe diagnostic")
	}
}
func TestStripConsumedRootsAndExcludedParents(t *testing.T) {
	dir := workspace(t)
	z := makeZIP(t, zip.Store, []string{"./", "./pkg/", "./pkg/sub/a"}, [][]byte{nil, nil, []byte("A")})
	p := writeFixture(t, dir, "strip.zip", z)
	got := invoke(t, "--nar", "--h1-go", "--strip-components=2", "--exclude=pkg/", "--format=json", p)
	empty := invoke(t, "--nar", "--h1-go", "--format=json", workspace(t))
	for i := range got {
		if got[i].Value != empty[i].Value {
			t.Errorf("exclusion did not preserve root identity: %s", got[i].Scheme)
		}
	}
}
func TestArchiveSymlinkResolutionRevisits(t *testing.T) {
	m := map[string]*entry{
		"":    {kind: 'd'},
		"d":   {kind: 'd'},
		"d/a": {kind: 'f'},
		"s":   {kind: 'l', target: []byte("d")},
		"x":   {kind: 'l', target: []byte("s/../s/a")},
	}
	got, err := resolveLink(m, "x")
	if err != nil || got != "d/a" {
		t.Fatalf("valid repeated symlink %q: %v", got, err)
	}
	m["s"].target = []byte("s/a")
	if _, err := resolveLink(m, "x"); err == nil {
		t.Fatal("accepted growing cycle")
	}
}
func TestPAXGlobalMetadata(t *testing.T) {
	dir := workspace(t)
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "GlobalHead", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "not an entry"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(&tar.Header{Name: "a", Mode: 0644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("x"))
	_ = w.Close()
	p := writeFixture(t, dir, "global.tar", b.Bytes())
	records := invoke(t, "--h1", "--strict", "--format=json", p)
	want := render(selection{"h1", "sha256"}, sum("sha256", []byte(hex.EncodeToString(sum("sha256", []byte("x")))+"  a\n")))
	if records[0].Value != want {
		t.Fatal("global PAX was included as content")
	}
	var globalSize bytes.Buffer
	writer := tar.NewWriter(&globalSize)
	_ = writer.WriteHeader(&tar.Header{Name: "Global", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"size": "1", "path": "renamed"}})
	_ = writer.WriteHeader(&tar.Header{Name: "original", Mode: 0644, Size: 1})
	_, _ = writer.Write([]byte("x"))
	_ = writer.Close()
	physical := globalSize.Bytes()
	regular := physical[1024:1536]
	copy(regular[124:136], []byte("00000000000\x00"))
	for i := 148; i < 156; i++ {
		regular[i] = ' '
	}
	checksum := 0
	for _, v := range regular {
		checksum += int(v)
	}
	copy(regular[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	globalPath := writeFixture(t, dir, "size.tar", physical)
	got := invoke(t, "--h1", "--nar", "--strict", "--format=json", globalPath)
	plain := workspace(t)
	_ = os.WriteFile(filepath.Join(plain, "renamed"), []byte("x"), 0644)
	wantRecords := invoke(t, "--h1", "--nar", "--format=json", plain)
	for i := range got {
		if got[i].Value != wantRecords[i].Value {
			t.Errorf("global size/path %s", got[i].Scheme)
		}
	}
}

func TestSeekableTARArchiveHardlinkDiscovery(t *testing.T) {
	dir := workspace(t)
	inner := makeZIP(t, zip.Deflate, []string{"a"}, [][]byte{[]byte("A")})
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	_ = w.WriteHeader(&tar.Header{Name: "alias.zip", Typeflag: tar.TypeLink, Linkname: "payload.bin", Mode: 0644})
	_ = w.WriteHeader(&tar.Header{Name: "payload.bin", Mode: 0644, Size: int64(len(inner))})
	_, _ = w.Write(inner)
	_ = w.Close()
	p := writeFixture(t, dir, "hard-archive.tar", b.Bytes())
	plain := invoke(t, "--h1", "--format=json", p)
	recursive := invoke(t, "--h1", "--recurse", "--format=json", p)
	if len(recursive) != 3 || recursive[0].Value != plain[0].Value || recursive[1].ArchiveEntries[0] != "alias.zip" || recursive[1].Value != recursive[2].Value {
		t.Fatal("hard-link discovery changed bytes, identity, order or omitted alias")
	}
	excluded := invoke(t, "--h1", "--recurse", "--exclude=payload.bin", "--format=json", p)
	if len(excluded) != 2 || excluded[1].ArchiveEntries[0] != "alias.zip" {
		t.Fatal("excluded target prevented alias discovery")
	}
	budget := fmt.Sprintf("--max-expanded-bytes=%d", 2*len(inner)+2)
	_ = invoke(t, "--h1", "--strict", "--recurse", budget, "--format=json", p)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write(b.Bytes())
	_ = gz.Close()
	gzPath := writeFixture(t, dir, "hard-archive.tgz", compressed.Bytes())
	nar := invoke(t, "--nar", "--strict", "--recurse", "--format=json", gzPath)
	if len(nar) != 3 || nar[1].Value != nar[2].Value {
		t.Fatal("NAR-only sequential archive aliases were omitted")
	}
	shared := invoke(t, "--h1", "--strict", "--recurse", "--format=json", gzPath)
	if len(shared) != 3 || shared[1].Value != shared[2].Value {
		t.Fatal("forward sequential archive aliases were not shared with target reads")
	}
}
