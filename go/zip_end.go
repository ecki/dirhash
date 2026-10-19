package main

import (
	"archive/zip"
	"io"
	"sync/atomic"
)

var zipInventoryAuditCount atomic.Uint64

type zipEndView struct {
	io.ReaderAt
	central, end int64
}

func (r *zipEndView) ReadAt(b []byte, offset int64) (int, error) {
	n := 0
	// archive/zip scans a large EOF window. Supply zeros before the known
	// central directory instead of rereading payload merely to search metadata.
	if offset < r.central && offset+int64(len(b)) > r.central {
		n = int(r.central - offset)
		clear(b[:n])
	}
	count, err := r.ReaderAt.ReadAt(b[n:], offset+int64(n))
	count += n
	for i := int(max(int64(0), r.end+22-offset)); i+4 <= count; i++ {
		if u32(b[i:]) == 0x06054b50 {
			b[i] = 0
		}
	}
	return count, err
}

// Search backwards within the EOCD/comment extent, validating each candidate's
// complete physical inventory. Valid inputs never require a payload search.
func accountedZIP(r io.ReaderAt, size int64, location string, inventory map[string][]byte) (*zip.Reader, error) {
	zipInventoryAuditCount.Add(1)
	var first error
	var signature [4]byte
	for offset := size - 22; offset >= max(int64(0), size-65557); offset-- {
		if _, err := r.ReadAt(signature[:], offset); err != nil {
			return nil, fail("ARCHIVE_LAYOUT", location, "truncated ZIP ending")
		}
		if u32(signature[:]) != 0x06054b50 {
			continue
		}
		local := map[string][]byte{}
		var central int64
		err := auditZIP(r, size, location, local, offset, &central)
		var z *zip.Reader
		if err == nil {
			z, err = zip.NewReader(&zipEndView{ReaderAt: r, central: central, end: offset}, size)
		}
		if err == nil {
			for name, extra := range local {
				inventory[name] = extra
			}
			return z, nil
		}
		if first == nil {
			first = archiveError(err, location, "invalid ZIP central directory")
		}
	}
	if first != nil {
		return nil, first
	}
	return nil, fail("ARCHIVE_LAYOUT", location, "ZIP does not end at its EOCD comment")
}
