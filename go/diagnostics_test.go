package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFailurePathIsReadableAndEscapesControls(t *testing.T) {
	windowsPath := `SPECIAL_FILE C:\Users\someone\root\archive.zip!/META-INF/bad!!.zip`
	err := (&failure{code: "SPECIAL_FILE", location: `C:\Users\someone\root\archive.zip!/META-INF/bad!!.zip`, reason: "bad file type", status: 1}).Error()
	if !strings.Contains(err, windowsPath) || strings.Contains(err, `C:\\Users`) || strings.Contains(err, `"C:\Users`) {
		t.Fatalf("Windows path is not human-readable: %q", err)
	}
	err = (&failure{code: "INVALID_PATH", location: "root/bad\n\u202efile", reason: "bad", status: 1}).Error()
	if strings.ContainsAny(err, "\n\u202e") || !strings.Contains(err, `bad\u{a}\u{202e}file`) {
		t.Fatalf("control/format characters were not safely escaped: %q", err)
	}
}

func TestFilesystemArchiveSuccessPathsUseNativePrefix(t *testing.T) {
	dir := workspace(t)
	inner := makeZIP(t, 0, []string{"a"}, [][]byte{[]byte("x")})
	_ = writeFixture(t, dir, "outer!.zip", makeZIP(t, 0, []string{"inner!.zip"}, [][]byte{inner}))
	got := invoke(t, "--h1", "--recurse", "--format=json", dir)
	outerPath := filepath.Join(dir, "outer!.zip")
	if len(got) != 3 || got[0].Path != dir ||
		got[1].Path != outerPath || len(got[1].ArchiveEntries) != 1 || got[1].ArchiveEntries[0] != "outer!.zip" ||
		got[2].Path != escaped(outerPath)+"!/inner!!.zip" ||
		len(got[2].ArchiveEntries) != 2 || got[2].ArchiveEntries[0] != "outer!.zip" || got[2].ArchiveEntries[1] != "inner!.zip" {
		t.Fatalf("unexpected successful result paths: %#v", got)
	}
	text := runOutput(t, "--h1", "--recurse", dir)
	if !strings.Contains(text, "\t"+outerPath+"\n") || !strings.Contains(text, "\t"+escaped(outerPath)+"!/inner!!.zip\n") {
		t.Fatalf("text output did not preserve native filesystem paths: %q", text)
	}
}

func TestInvalidFilesystemNameDiagnosticHasNoArchiveBoundary(t *testing.T) {
	dir := workspace(t)
	path := writeFixture(t, dir, "bad\u200d.txt", []byte("x"))
	var out, diagnostics bytes.Buffer
	status := run([]string{"--h1", "--strict", dir}, &out, &diagnostics)
	if status != 1 || out.Len() != 0 || !strings.Contains(diagnostics.String(), diagnosticText(path)) || strings.Contains(diagnostics.String(), "!/") {
		t.Fatalf("status=%d out=%q diagnostics=%s", status, &out, &diagnostics)
	}
}

func TestFilesystemDiagnosticHasNoArchiveBoundary(t *testing.T) {
	dir := workspace(t)
	path := writeFixture(t, dir, "bad!.zip", []byte("not an archive"))
	var out, diagnostics bytes.Buffer
	status := run([]string{"--h1", "--recurse", dir}, &out, &diagnostics)
	if status != 1 || out.Len() != 0 || !strings.Contains(diagnostics.String(), diagnosticText(path)) || strings.Contains(diagnostics.String(), "!/") {
		t.Fatalf("status=%d out=%q diagnostics=%s", status, &out, &diagnostics)
	}
}

func TestDirectoryContainedArchiveDiagnosticHasOnlyRealBoundary(t *testing.T) {
	dir := workspace(t)
	path := writeFixture(t, dir, "outer!.zip", makeZIP(t, 0, []string{"bad!.zip"}, [][]byte{[]byte("not an archive")}))
	var out, diagnostics bytes.Buffer
	status := run([]string{"--h1", "--recurse", path}, &out, &diagnostics)
	want := escaped(path) + "!/bad!!.zip"
	if status != 1 || out.Len() != 0 || !strings.Contains(diagnostics.String(), diagnosticText(want)) {
		t.Fatalf("status=%d out=%q diagnostics=%s want=%s", status, &out, &diagnostics, want)
	}
}

func TestUnsupportedZIPModeReportsEntryAndUnixType(t *testing.T) {
	dir := workspace(t)
	data := makeZIP(t, 0, []string{"META-INF/maven/"}, [][]byte{nil})
	central := bytes.Index(data, []byte("PK\x01\x02"))
	if central < 0 {
		t.Fatal("ZIP central header missing")
	}
	data[central+5] = 3
	binary.LittleEndian.PutUint16(data[central+40:central+42], 0xffff)
	path := writeFixture(t, dir, "invalid-mode.zip", data)
	var out, diagnostics bytes.Buffer
	status := run([]string{"--plain", "--h1", "--format=json", path}, &out, &diagnostics)
	wantWarning := "WARN_ZIP_DIRECTORY_MODE: " + path + "!/META-INF/maven/: accepted malformed empty ZIP directory with Unix mode 0177777\n"
	if diagnostics.String() != wantWarning {
		t.Errorf("got warning %q, want %q", diagnostics.String(), wantWarning)
	}
	if status != 0 || out.Len() == 0 || strings.Count(diagnostics.String(), "WARN_ZIP_DIRECTORY_MODE") != 1 {
		t.Fatalf("status=%d stdout=%q stderr=%s", status, &out, &diagnostics)
	}
	if !strings.Contains(out.String(), `"scheme":"plain"`) {
		t.Fatalf("plain result omitted: %s", &out)
	}
	out.Reset()
	diagnostics.Reset()
	status = run([]string{"--plain", "--h1", "--strict", path}, &out, &diagnostics)
	for _, fragment := range []string{path + "!/META-INF/maven/", "Unix mode 0177777", "type bits 0170000"} {
		if !strings.Contains(diagnostics.String(), fragment) {
			t.Errorf("strict diagnostic %q does not contain %q", diagnostics.String(), fragment)
		}
	}
	if status != 1 || out.Len() != 0 || strings.Contains(diagnostics.String(), "WARN_") {
		t.Fatalf("strict mode status=%d stdout=%q stderr=%s", status, &out, &diagnostics)
	}
}

func TestMalformedZIPDirectoryModeCompatibilityIsNarrowAndAtomic(t *testing.T) {
	dir := workspace(t)
	makeBadMode := func(fileName, name string, content []byte, appendDirectorySlash bool) string {
		data := makeZIP(t, 0, []string{name}, [][]byte{content})
		central := bytes.Index(data, []byte("PK\x01\x02"))
		if central < 0 {
			t.Fatal("ZIP central header missing")
		}
		if appendDirectorySlash {
			local := bytes.Index(data, []byte("PK\x03\x04"))
			if local < 0 {
				t.Fatal("ZIP local header missing")
			}
			localNameEnd := local + 30 + int(binary.LittleEndian.Uint16(data[local+26:local+28]))
			data = append(data[:localNameEnd], append([]byte{'/'}, data[localNameEnd:]...)...)
			central++
			centralNameEnd := central + 46 + int(binary.LittleEndian.Uint16(data[central+28:central+30]))
			data = append(data[:centralNameEnd], append([]byte{'/'}, data[centralNameEnd:]...)...)
			binary.LittleEndian.PutUint16(data[local+26:local+28], uint16(len(name)+1))
			binary.LittleEndian.PutUint16(data[central+28:central+30], uint16(len(name)+1))
			eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
			if eocd < 0 {
				t.Fatal("ZIP end record missing")
			}
			binary.LittleEndian.PutUint32(data[eocd+12:eocd+16], binary.LittleEndian.Uint32(data[eocd+12:eocd+16])+1)
			binary.LittleEndian.PutUint32(data[eocd+16:eocd+20], uint32(central))
			central = bytes.Index(data, []byte("PK\x01\x02"))
		}
		data[central+5] = 3
		binary.LittleEndian.PutUint16(data[central+40:central+42], 0xffff)
		return writeFixture(t, dir, fileName, data)
	}
	for _, fixture := range []string{
		makeBadMode("missing-slash.zip", "META-INF/maven", nil, false),
		makeBadMode("nonempty.zip", "META-INF/maven", []byte("x"), true),
	} {
		rejected(t, 1, "SPECIAL_FILE", "--plain", fixture)
	}

	// A valid legacy marker followed by a corrupt entry must not leak a warning.
	data := makeZIP(t, 0, []string{"META-INF/maven/", "payload"}, [][]byte{nil, []byte("x")})
	firstCentral := bytes.Index(data, []byte("PK\x01\x02"))
	data[firstCentral+5] = 3
	binary.LittleEndian.PutUint16(data[firstCentral+40:firstCentral+42], 0xffff)
	local := bytes.Index(data, []byte("PK\x03\x04"))
	nameLength := int(data[local+26]) | int(data[local+27])<<8
	extraLength := int(data[local+28]) | int(data[local+29])<<8
	data[local+30+nameLength+extraLength] ^= 1
	path := writeFixture(t, dir, "bad-after-warning.zip", data)
	var out, diagnostics bytes.Buffer
	status := run([]string{"--plain", "--recurse", path}, &out, &diagnostics)
	if status == 0 || out.Len() != 0 || strings.Contains(diagnostics.String(), "WARN_ZIP_DIRECTORY_MODE") {
		t.Fatalf("invalid archive status=%d stdout=%q stderr=%s", status, &out, &diagnostics)
	}

	nestedZip := makeBadMode("nested-mode.zip", "META-INF/maven/", nil, false)
	outer := writeFixture(t, dir, "outer.tar", plainTAR(t, "inner.zip", readBytes(t, nestedZip)))
	out.Reset()
	diagnostics.Reset()
	status = run([]string{"--nar", "--plain", "--recurse", "--format=json", outer}, &out, &diagnostics)
	if status != 0 || out.Len() == 0 || strings.Count(diagnostics.String(), "WARN_ZIP_DIRECTORY_MODE") != 1 ||
		!strings.Contains(diagnostics.String(), outer+"!/inner.zip!/META-INF/maven/") {
		t.Fatalf("nested compatibility warning status=%d stdout=%q stderr=%s", status, &out, &diagnostics)
	}
	out.Reset()
	diagnostics.Reset()
	status = run([]string{"--nar", "--plain", "--strict", "--recurse", "--format=json", outer}, &out, &diagnostics)
	if status != 1 || out.Len() != 0 || strings.Contains(diagnostics.String(), "WARN_ZIP_DIRECTORY_MODE") {
		t.Fatalf("nested strict mode status=%d stdout=%q stderr=%s", status, &out, &diagnostics)
	}
}

func TestChangedFilesystemObjectCapturesItsOwnPath(t *testing.T) {
	dir := workspace(t)
	path := writeFixture(t, dir, "first!.txt", []byte("original"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	o, err := parse([]string{"--h1", dir})
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(o)
	tree, err := engine.newNamespace(nil, "directory", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	open := stableOpener(path, info, tree.entryLocation(filepath.Base(path)))
	if err := os.WriteFile(path, []byte("changed length"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = open()
	if err == nil || !strings.Contains(err.Error(), diagnosticText(path)) || strings.Contains(err.Error(), "!/") {
		t.Fatalf("wrong changed-object location: %v", err)
	}
}

func TestDeferredDirectoryVerificationReportsChangedChild(t *testing.T) {
	dir := workspace(t)
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := writeFixture(t, dir, "first!.txt", []byte("original"))
	_ = writeFixture(t, dir, "last.txt", []byte("last"))
	o, err := parse([]string{"--h1", dir})
	if err != nil {
		t.Fatal(err)
	}
	engine := newEngine(o)
	tree, err := engine.newNamespace(nil, "directory", nil, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.directory(tree, dir); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := engine.checks[0](); err == nil || !strings.Contains(err.Error(), diagnosticText(path)) || strings.Contains(err.Error(), "!/") {
		t.Fatalf("wrong deferred changed-child location: %v", err)
	}
}
