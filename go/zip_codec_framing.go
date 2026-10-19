package main

import (
	"compress/bzip2"
	"io"

	"github.com/klauspost/compress/zstd"
)

type codecLookahead struct {
	source *zipInput
	last   [2]byte
	count  int
}

func (r *codecLookahead) remember(b byte) {
	r.last[0], r.last[1] = r.last[1], b
	if r.count < 2 {
		r.count++
	}
}
func (r *codecLookahead) Read(b []byte) (int, error) {
	n, err := r.source.Read(b)
	for _, v := range b[:n] {
		r.remember(v)
	}
	return n, err
}
func (r *codecLookahead) ReadByte() (byte, error) {
	b, err := r.source.ReadByte()
	if err == nil {
		r.remember(b)
	}
	return b, err
}

type framedCodec struct {
	io.ReadCloser
	tail   *codecLookahead
	method uint16
	ended  bool
}

func (r *framedCodec) Read(b []byte) (int, error) {
	if r.ended {
		return 0, io.EOF
	}
	n, err := r.ReadCloser.Read(b)
	rewind := 0
	// These pinned decoders validate their footer before probing the following
	// stream. Restore only that documented, bounded continuation lookahead.
	if r.method == 12 && err == bzip2.StructuralError("bad magic value in continuation file") {
		rewind = 2
	}
	if r.method == 95 && err != nil && err.Error() == "xz: unexpected data after stream" {
		rewind = 1
	}
	if rewind > 0 && r.tail.count >= rewind {
		r.tail.source.unread(r.tail.last[2-rewind:])
		r.ended = true
		err = io.EOF
	}
	return n, err
}

// zstdFrames bounds the established decoder to complete frame records; it
// interprets framing only and never inspects compressed entropy data.
type zstdFrames struct {
	source      *zipInput
	remaining   int64
	phase       byte
	last, check bool
	seen        bool
}

func (r *zstdFrames) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if r.remaining > 0 {
			n, err := r.source.Read(b[:min(int64(len(b)), r.remaining)])
			r.remaining -= int64(n)
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		switch r.phase {
		case 0:
			magic := r.source.peek(4)
			if len(magic) != 4 {
				return 0, io.ErrUnexpectedEOF
			}
			if u32(magic) != 0xfd2fb528 && u32(magic)&0xfffffff0 != 0x184d2a50 {
				if r.seen {
					return 0, io.EOF
				}
				return 0, fail("ARCHIVE_INTEGRITY", "", "invalid Zstandard frame")
			}
			var h zstd.Header
			if err := h.Decode(r.source.peek(18)); err != nil {
				return 0, err
			}
			r.seen = true
			r.check = h.HasCheckSum
			r.remaining = int64(h.HeaderSize)
			r.phase = 1
			if h.Skippable {
				r.remaining += int64(h.SkippableSize)
				r.phase = 0
			}
		case 1:
			h := r.source.peek(3)
			if len(h) != 3 {
				return 0, io.ErrUnexpectedEOF
			}
			header := uint32(h[0]) | uint32(h[1])<<8 | uint32(h[2])<<16
			r.last = header&1 != 0
			size := header >> 3
			switch header >> 1 & 3 {
			case 1:
				size = 1
			case 3:
				return 0, fail("ARCHIVE_INTEGRITY", "", "reserved Zstandard block type")
			}
			r.remaining = 3 + int64(size)
			r.phase = 2
		case 2:
			if !r.last {
				r.phase = 1
				continue
			}
			r.phase = 0
			if r.check {
				r.remaining = 4
			}
		}
	}
}
