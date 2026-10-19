package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestRun(t *testing.T) {
	if version != "dirhash 0.1.0\n" {
		t.Fatalf("unexpected version string %q", version)
	}
	tests := []struct {
		name   string
		args   []string
		status int
		out    string
		errOut string
	}{
		{"help", []string{"--help"}, 0, help, ""},
		{"version", []string{"--version"}, 0, version, ""},
		{"missing arguments", nil, 2, "", "USAGE_ERROR: exactly one explicit input is required\n" + quickUsage},
		{"unknown selection", []string{"--h2", "."}, 2, "", "USAGE_ERROR: unknown option \"--h2\"\n" + quickUsage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			status := run(tt.args, &out, &errOut)
			if status != tt.status || out.String() != tt.out || errOut.String() != tt.errOut {
				t.Fatalf("got (%d, %q, %q), want (%d, %q, %q)",
					status, out.String(), errOut.String(), tt.status, tt.out, tt.errOut)
			}
		})
	}
}

type brokenWriter struct{}

func TestTextPath(t *testing.T) {
	path := ".\\folder\\a \"quoted\"\t\n\x01.zip"
	want := ".\\folder\\a \"quoted\"\\t\\n\\u0001.zip"
	if got := textPath(path); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	got := string(publish(&options{format: "text"}, []record{{Path: path, Scheme: "h1", DigestAlgorithm: "sha256", Value: "hash"}}))
	if wantLine := "h1\thash\t" + want + "\n"; got != wantLine {
		t.Fatalf("got %q, want %q", got, wantLine)
	}

}

func TestTextSchemeLabels(t *testing.T) {
	for _, scheme := range schemes {
		for _, digest := range algorithms {
			want := scheme + ":" + digest
			if ((scheme == "gittree" || scheme == "swhid") && digest == "sha1") ||
				(scheme != "gittree" && scheme != "swhid" && digest == "sha256") {
				want = scheme
			}
			got := string(publish(&options{format: "text"}, []record{{Scheme: scheme, DigestAlgorithm: digest, Value: "hash", Path: "."}}))
			if got != want+"\thash\t.\n" {
				t.Fatalf("%s/%s: got %q", scheme, digest, got)
			}
		}
	}
}

func (brokenWriter) Write([]byte) (int, error) {
	return 0, errors.New("test output failure")
}

func TestOutputFailure(t *testing.T) {
	var errOut bytes.Buffer
	if status := run([]string{"--help"}, brokenWriter{}, &errOut); status != 4 {
		t.Fatalf("got status %d, want 4", status)
	}
	if got := errOut.String(); got != "IO_ERROR: failed to write CLI output.\n" {
		t.Fatalf("unexpected diagnostic: %q", got)
	}
}
