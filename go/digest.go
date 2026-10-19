package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

func digest(name string) hash.Hash {
	switch name {
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "blake2b-256":
		h, _ := blake2b.New256(nil)
		return h
	case "blake2b-512":
		h, _ := blake2b.New512(nil)
		return h
	case "blake3":
		return blake3.New()
	case "sha3-256":
		return sha3.New256()
	case "sha3-512":
		return sha3.New512()
	}
	panic("unvalidated digest")
}
func sum(algorithm string, b []byte) []byte {
	h := digest(algorithm)
	_, _ = h.Write(b)
	return h.Sum(nil)
}
func object(algorithm, kind string, b []byte) []byte {
	h := digest(algorithm)
	_, _ = fmt.Fprintf(h, "%s %d%c", kind, len(b), 0)
	_, _ = h.Write(b)
	return h.Sum(nil)
}
func render(s selection, b []byte) string {
	x := hex.EncodeToString(b)
	switch {
	case (s.scheme == "h1" || s.scheme == "h1-go") && s.algorithm == "sha256":
		return "h1:" + base64.StdEncoding.EncodeToString(b)
	case s.scheme == "gittree" && (s.algorithm == "sha1" || s.algorithm == "sha256"):
		return x
	case s.scheme == "swhid" && s.algorithm == "sha1":
		return "swh:1:dir:" + x
	case s.scheme == "nar" && s.algorithm == "sha256":
		return "sha256-" + base64.StdEncoding.EncodeToString(b)
	case s.scheme == "plain":
		return s.algorithm + ":" + x
	default:
		return "dirhash:1:" + s.scheme + ":" + s.algorithm + ":" + x
	}
}
