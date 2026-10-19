package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeekableZIPNARUsesOneInventoryAuditPerArchive(t *testing.T) {
	for _, count := range []int{100, 500, 1000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			dir := workspace(t)
			names := make([]string, count)
			contents := make([][]byte, count)
			tree := filepath.Join(dir, "tree")
			if err := os.Mkdir(tree, 0700); err != nil {
				t.Fatal(err)
			}
			for i := range names {
				names[i] = fmt.Sprintf("f%06d", i)
				contents[i] = []byte("x")
				if err := os.WriteFile(filepath.Join(tree, names[i]), contents[i], 0600); err != nil {
					t.Fatal(err)
				}
			}
			archive := writeFixture(t, dir, "many.zip", makeZIP(t, zip.Store, names, contents))

			selectedAlgorithms := algorithms
			if count > 100 {
				selectedAlgorithms = []string{"sha256"}
			}
			args := []string{"--format=json"}
			for _, algorithm := range selectedAlgorithms {
				args = append(args, "--nar:"+algorithm)
			}
			options, err := parse(append(append([]string{}, args...), archive))
			if err != nil {
				t.Fatal(err)
			}
			before := zipInventoryAuditCount.Load()
			engine := newEngine(options)
			started := time.Now()
			actual, err := engine.execute()
			elapsed := time.Since(started)
			if err != nil {
				t.Fatal(err)
			}
			if audits := zipInventoryAuditCount.Load() - before; audits != 1 {
				t.Fatalf("ZIP_STORED with %d files performed %d inventory audits; want 1", count, audits)
			}

			directoryArgs := append([]string{"--format=json"}, args[1:]...)
			expected := invoke(t, append(directoryArgs, tree)...)
			if len(actual) != len(expected) {
				t.Fatalf("got %d NAR values, want %d", len(actual), len(expected))
			}
			for i := range actual {
				if actual[i].Scheme != expected[i].Scheme || actual[i].DigestAlgorithm != expected[i].DigestAlgorithm || actual[i].Value != expected[i].Value {
					t.Errorf("%s: ZIP value %s differs from directory %s", actual[i].DigestAlgorithm, actual[i].Value, expected[i].Value)
				}
			}
			t.Logf("%d ZIP_STORED entries: %s, one central inventory audit, all digest overrides match the directory", count, elapsed.Round(time.Millisecond))
		})
	}
}
