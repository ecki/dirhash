package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPTransferPolicyAndCleanup(t *testing.T) {
	payload := makeZIP(t, 0, []string{"a"}, [][]byte{[]byte("remote")})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("identity coding not requested")
			}
			_, _ = w.Write(payload)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/coding":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(payload)
		case "/truncated":
			w.Header().Set("Content-Length", "10000")
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("TMP", temp)
	t.Setenv("TEMP", temp)
	before, _ := filepath.Glob(".dirhash-download-*")
	source := server.URL + "/redirect"
	got := invoke(t, "--h1", "--format=json", source)
	if got[0].Source != source || got[0].Path != source || got[0].InputType != "zip" {
		t.Fatal("download exposed private path")
	}
	for _, suffix := range []string{"/loop", "/coding", "/truncated", "/missing"} {
		rejected(t, 4, "NETWORK_ERROR", "--h1", server.URL+suffix)
	}
	rejected(t, 1, "LIMIT_EXCEEDED", "--h1", "--max-download-bytes=0", server.URL+"/ok")
	after, _ := filepath.Glob(".dirhash-download-*")
	if len(before) != len(after) {
		t.Fatal("download directory leaked")
	}
	if leaked, _ := filepath.Glob(filepath.Join(temp, ".dirhash-download-*")); len(leaked) != 0 {
		t.Fatal("download directory leaked in OS temporary directory")
	}
	var out, errOut bytes.Buffer
	credentialSource := strings.Replace(server.URL, "http://", "http://secret-user:secret-password@", 1) + "/ok"
	if code := run([]string{"--h1", credentialSource}, &out, &errOut); code != 4 {
		t.Fatal(code)
	}
	if strings.Contains(errOut.String(), "secret-") {
		t.Fatal("URL credentials leaked")
	}
}
func TestDownloadDirectoryUsesOSTemp(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("TMP", temp)
	t.Setenv("TEMP", temp)
	dir, err := privateDownloadDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	want, err := filepath.EvalSymlinks(temp)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(dir) != want || !strings.HasPrefix(filepath.Base(dir), ".dirhash-download-") {
		t.Fatalf("download directory %q not in %q", dir, want)
	}
}

func TestHTTPUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "never trusted") }))
	defer server.Close()
	rejected(t, 4, "NETWORK_ERROR", "--h1", server.URL)
}

func TestCancelledInvocationIsAtomic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	status := runContext(ctx, []string{"--h1", workspace(t)}, &out, &errOut)
	if status != 4 || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "IO_ERROR") {
		t.Fatalf("%d %q %q", status, &out, &errOut)
	}
}
