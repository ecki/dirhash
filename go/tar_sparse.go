package main

import (
	"bytes"
	"io"
	"sort"
	"strconv"
	"strings"
)

type extent struct{ offset, length, physical int64 }

func legacySparseExtents(b []byte, count int) ([]extent, error) {
	var result []extent
	for i := 0; i < count; i++ {
		offset, err := tarNumber(b[i*24 : i*24+12])
		if err != nil {
			return nil, err
		}
		length, err := tarNumber(b[i*24+12 : i*24+24])
		if err != nil {
			return nil, err
		}
		if length != 0 {
			result = append(result, extent{offset: offset, length: length})
		}
	}
	return result, nil
}
func paxSparseExtents(value string) ([]extent, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts)%2 != 0 {
		return nil, fail("ARCHIVE_INTEGRITY", "", "invalid sparse map pair count")
	}
	var result []extent
	for i := 0; i < len(parts); i += 2 {
		offset, err := strconv.ParseInt(parts[i], 10, 64)
		if err != nil {
			return nil, err
		}
		length, err := strconv.ParseInt(parts[i+1], 10, 64)
		if err != nil {
			return nil, err
		}
		if length != 0 {
			result = append(result, extent{offset: offset, length: length})
		}
	}
	return result, nil
}
func finalizeExtents(list []extent, size int64) ([]extent, error) {
	result := append([]extent{}, list...)
	var previous, physical int64
	for i := range result {
		e := &result[i]
		if e.offset < previous || e.length < 0 || e.offset > size || e.length > size-e.offset {
			return nil, fail("ARCHIVE_INTEGRITY", "", "overlapping or out-of-range sparse extents")
		}
		e.physical = physical
		physical += e.length
		previous = e.offset + e.length
	}
	return result, nil
}
func (a *tarAudit) sparseMapBlock(b []byte) error {
	if !a.captureSparse {
		return nil
	}
	if len(a.sparseBuffer)+len(b) > 1<<20 {
		return fail("LIMIT_EXCEEDED", a.location, "sparse map exceeds bounded metadata representation")
	}
	a.sparseBuffer = append(a.sparseBuffer, b...)
	for {
		index := bytes.IndexByte(a.sparseBuffer[a.sparseCursor:], '\n')
		if index < 0 {
			return nil
		}
		index += a.sparseCursor
		n, err := strconv.ParseInt(string(a.sparseBuffer[a.sparseCursor:index]), 10, 64)
		if err != nil || n < 0 {
			return fail("ARCHIVE_INTEGRITY", a.location, "invalid sparse map integer")
		}
		a.sparseCursor = index + 1
		if a.sparseCount < 0 {
			if n > 65536 {
				return fail("LIMIT_EXCEEDED", a.location, "sparse extent count exceeds bounded metadata representation")
			}
			a.sparseCount = n
		} else {
			a.sparseValues = append(a.sparseValues, n)
		}
		if int64(len(a.sparseValues)) == a.sparseCount*2 {
			a.sparseExtents = nil
			for i := 0; i < len(a.sparseValues); i += 2 {
				if a.sparseValues[i+1] != 0 {
					a.sparseExtents = append(a.sparseExtents, extent{offset: a.sparseValues[i], length: a.sparseValues[i+1]})
				}
			}
			if a.strict {
				for _, v := range a.sparseBuffer[a.sparseCursor:] {
					if v != 0 {
						return fail("ARCHIVE_LAYOUT", a.location, "nonzero sparse-map block padding")
					}
				}
			}
			a.captureSparse = false
			a.sparseBuffer = nil
			a.sparseValues = nil
			return nil
		}
	}
}

type sparseRange struct {
	source                io.ReaderAt
	close                 io.Closer
	extents               []extent
	start, size, position int64
}

func (r *sparseRange) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fail("IO_ERROR", "", "negative sparse read offset")
	}
	if offset >= r.size {
		return 0, io.EOF
	}
	want := len(b)
	if int64(len(b)) > r.size-offset {
		b = b[:r.size-offset]
	}
	done := 0
	for len(b) > 0 {
		index := sort.Search(len(r.extents), func(i int) bool { return r.extents[i].offset+r.extents[i].length > offset })
		if index == len(r.extents) || offset < r.extents[index].offset {
			end := r.size
			if index < len(r.extents) {
				end = r.extents[index].offset
			}
			n := min(int64(len(b)), end-offset)
			clear(b[:n])
			done += int(n)
			offset += n
			b = b[n:]
			continue
		}
		e := r.extents[index]
		n := min(int64(len(b)), e.offset+e.length-offset)
		count, err := r.source.ReadAt(b[:n], r.start+e.physical+offset-e.offset)
		done += count
		offset += int64(count)
		b = b[count:]
		if err != nil {
			return done, err
		}
		if int64(count) != n {
			return done, io.ErrUnexpectedEOF
		}
	}
	if done < want {
		return done, io.EOF
	}
	return done, nil
}
func (r *sparseRange) Read(b []byte) (int, error) {
	n, err := r.ReadAt(b, r.position)
	r.position += int64(n)
	return n, err
}
func (r *sparseRange) Close() error { return r.close.Close() }
func sparseRangeOpener(open opener, offset, size int64, list []extent) opener {
	return func() (io.ReadCloser, error) {
		root, err := open()
		if err != nil {
			return nil, err
		}
		readerAt, ok := root.(io.ReaderAt)
		if !ok {
			_ = root.Close()
			return nil, fail("UNSUPPORTED_STREAMING", "", "sparse source is not seekable")
		}
		return &sparseRange{source: readerAt, close: root, extents: list, start: offset, size: size}, nil
	}
}
