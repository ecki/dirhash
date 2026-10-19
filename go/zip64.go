package main

import (
	"bytes"
	"io"
)

func zip64Extensions(r io.Reader, size uint64) error {
	for size > 0 {
		if size < 6 {
			return fail("ARCHIVE_LAYOUT", "", "truncated ZIP64 extensible field")
		}
		var header [6]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return fail("ARCHIVE_LAYOUT", "", "truncated ZIP64 extensible sector")
		}
		size -= 6
		length := uint64(u32(header[2:]))
		if length > size {
			return fail("ARCHIVE_LAYOUT", "", "ZIP64 extensible field exceeds its sector")
		}
		if u16(header[:]) != 0x0065 {
			return fail("UNSUPPORTED_FORMAT", "", "unsupported ZIP64 extensible field")
		}
		if length != 25 {
			return fail("ARCHIVE_LAYOUT", "", "invalid ZIP64 Z390 field size")
		}
		var body [25]byte
		if _, err := io.ReadFull(r, body[:]); err != nil {
			return fail("ARCHIVE_LAYOUT", "", "truncated ZIP64 Z390 metadata")
		}
		if !bytes.Equal(body[:4], []byte{0xe9, 0xf3, 0xf9, 0xf0}) {
			return fail("ARCHIVE_LAYOUT", "", "invalid ZIP64 Z390 identifier")
		}
		size -= length
	}
	return nil
}
