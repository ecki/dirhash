package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func sharedRows(t *testing.T, name string, columns int) [][]string {
	t.Helper()
	root := os.Getenv("DIRHASH_TEST_VECTORS")
	if root == "" {
		root = filepath.Join("..", "tests", "vectors")
	}
	f, err := os.Open(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	var rows [][]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != columns {
			t.Fatalf("%s: expected %d fields: %q", name, columns, line)
		}
		rows = append(rows, fields)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s contains no vectors", name)
	}
	return rows
}

func TestSharedConstructionVectors(t *testing.T) {
	trees := map[string][][]string{}
	for _, row := range sharedRows(t, "trees.tsv", 5) {
		trees[row[0]] = append(trees[row[0]], row)
	}
	hashes := map[string][][]string{}
	for _, row := range sharedRows(t, "hashes.tsv", 4) {
		hashes[row[0]] = append(hashes[row[0]], row)
	}
	for _, name := range sortedKeys(hashes) {
		t.Run(name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			for _, row := range trees[name] {
				mode, err := strconv.ParseUint(row[3], 8, 32)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := hex.DecodeString(row[4])
				if err != nil {
					t.Fatal(err)
				}
				header := &zip.FileHeader{Name: row[1], Method: zip.Store}
				permissions := os.FileMode(mode)
				switch row[2] {
				case "dir":
					header.Name += "/"
					permissions |= os.ModeDir
				case "link":
					permissions |= os.ModeSymlink
				case "file":
				default:
					t.Fatalf("unknown shared vector kind %q", row[2])
				}
				header.SetMode(permissions)
				file, err := writer.CreateHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = file.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			path := writeFixture(t, workspace(t), name+".zip", archive.Bytes())
			args := []string{"--strict", "--format=json"}
			for _, row := range hashes[name] {
				args = append(args, "--"+row[1]+":"+row[2])
			}
			actual := invoke(t, append(args, path)...)
			if len(actual) != len(hashes[name]) {
				t.Fatalf("expected %d records, got %d", len(hashes[name]), len(actual))
			}
			for i, expected := range hashes[name] {
				if actual[i].Scheme != expected[1] || actual[i].DigestAlgorithm != expected[2] || actual[i].Value != expected[3] {
					t.Errorf("%s/%s/%s: got %s; want %s", name, expected[1], expected[2], actual[i].Value, expected[3])
				}
			}
		})
	}
	for name := range trees {
		if len(hashes[name]) == 0 {
			t.Fatalf("tree vector %q has no expected hashes", name)
		}
	}
}
