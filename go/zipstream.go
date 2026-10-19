package main

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"github.com/ulikunitz/xz"
)

type zipInput struct {
	r       *bufio.Reader
	offset  int64
	pending []byte
}

func (r *zipInput) Read(b []byte) (int, error) {
	if len(r.pending) > 0 {
		n := copy(b, r.pending)
		r.pending = r.pending[n:]
		r.offset += int64(n)
		return n, nil
	}
	n, e := r.r.Read(b)
	r.offset += int64(n)
	return n, e
}
func (r *zipInput) ReadByte() (byte, error) {
	if len(r.pending) > 0 {
		b := r.pending[0]
		r.pending = r.pending[1:]
		r.offset++
		return b, nil
	}
	b, e := r.r.ReadByte()
	if e == nil {
		r.offset++
	}
	return b, e
}
func (r *zipInput) peek(n int) []byte {
	if len(r.pending) >= n {
		return r.pending[:n]
	}
	b, _ := r.r.Peek(n - len(r.pending))
	return append(append([]byte{}, r.pending...), b...)
}
func (r *zipInput) unread(b []byte) {
	r.pending = append(append([]byte{}, b...), r.pending...)
	r.offset -= int64(len(b))
}
func (r *zipInput) take(n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}

type localZIP struct {
	offset               int64
	raw, extra           []byte
	flags, method        uint16
	crc                  uint32
	compressed, expanded uint64
	zip64, deferred      bool
	boundKnown           bool
	nameKnown            bool
	entry                *entry
}

func nextLocal(r *zipInput) (*localZIP, uint32, error) {
	offset := r.offset
	b, err := r.take(4)
	if err != nil {
		return nil, 0, err
	}
	signature := u32(b)
	if signature != 0x04034b50 {
		return nil, signature, nil
	}
	h, err := r.take(26)
	if err != nil {
		return nil, 0, err
	}
	l := &localZIP{offset: offset, flags: u16(h[2:]), method: u16(h[4:]), crc: u32(h[10:]), compressed: uint64(u32(h[14:])), expanded: uint64(u32(h[18:]))}
	l.deferred = l.flags&8 != 0
	nl, xl := int(u16(h[22:])), int(u16(h[24:]))
	b, err = r.take(nl + xl)
	if err != nil {
		return nil, 0, err
	}
	l.raw = b[:nl]
	l.extra = b[nl:]
	fields, err := zipExtras(l.extra)
	if err != nil {
		return nil, 0, err
	}
	x := fields[1]
	if len(x) >= 16 {
		l.zip64 = true
	}
	if l.expanded == 0xffffffff {
		l.zip64 = true
		if len(x) < 8 {
			return nil, 0, fail("ARCHIVE_INTEGRITY", "", "missing ZIP64 size")
		}
		l.expanded = u64(x)
		x = x[8:]
	}
	if l.compressed == 0xffffffff {
		l.zip64 = true
		if len(x) < 8 {
			return nil, 0, fail("ARCHIVE_INTEGRITY", "", "missing ZIP64 size")
		}
		l.compressed = u64(x)
	}
	if err = zipFlags(l.flags); err != nil {
		return nil, 0, err
	}
	if !supportedMethod(l.method) {
		return nil, 0, fail("UNSUPPORTED_METHOD", "", "unsupported ZIP method")
	}
	return l, signature, nil
}

type streamedPayload struct {
	reader  io.ReadCloser
	limited *io.LimitedReader
	crc     hashCRC
	count   int64
	start   int64
}
type hashCRC interface {
	io.Writer
	Sum32() uint32
}

func (p *streamedPayload) Read(b []byte) (int, error) {
	n, e := p.reader.Read(b)
	if n > 0 {
		_, _ = p.crc.Write(b[:n])
		p.count += int64(n)
	}
	return n, e
}
func openLocal(r *zipInput, l *localZIP) (*streamedPayload, error) {
	start := r.offset
	var source io.Reader = r
	var limited *io.LimitedReader
	if !l.deferred || l.compressed > 0 || l.boundKnown {
		if l.compressed > uint64(^uint64(0)>>1) {
			return nil, fail("LIMIT_EXCEEDED", "", "ZIP compressed size exceeds representation limit")
		}
		limited = &io.LimitedReader{R: r, N: int64(l.compressed)}
		source = limited
	} else if l.method == 20 || l.method == 93 {
		source = &zstdFrames{source: r}
	} else if l.method != 8 && l.method != 12 && l.method != 95 {
		return nil, fail("UNSUPPORTED_STREAMING", "", "deferred ZIP size requires unavailable streaming codec framing")
	}
	var reader io.ReadCloser
	var err error
	if limited == nil && (l.method == 12 || l.method == 95) {
		tail := &codecLookahead{source: r}
		if l.method == 95 {
			var x *xz.Reader
			x, err = (xz.ReaderConfig{SingleStream: true}).NewReader(tail)
			if err == nil {
				reader = io.NopCloser(x)
			}
		} else {
			reader, err = zipCodec(l.method, tail)
		}
		if err == nil {
			reader = &framedCodec{ReadCloser: reader, tail: tail, method: l.method}
		}
	} else {
		reader, err = zipCodec(l.method, source)
	}
	if err != nil {
		return nil, err
	}
	return &streamedPayload{reader: reader, limited: limited, crc: crc32.NewIEEE(), start: start}, nil
}
func finishLocal(r *zipInput, l *localZIP, p *streamedPayload) error {
	if _, err := io.CopyBuffer(io.Discard, p, make([]byte, 32768)); err != nil {
		return err
	}
	if err := p.reader.Close(); err != nil {
		return err
	}
	if p.limited != nil && p.limited.N != 0 {
		return fail("ARCHIVE_INTEGRITY", "", "ZIP compressed stream ended before its declared boundary")
	}
	actualCompressed := uint64(r.offset - p.start)
	if l.deferred {
		if l.crc != 0 && l.crc != p.crc.Sum32() || l.compressed != 0 && l.compressed != actualCompressed || l.expanded != 0 && l.expanded != uint64(p.count) {
			return fail("ARCHIVE_LAYOUT", "", "invalid ZIP descriptor placeholders")
		}
		width := 12
		if l.zip64 {
			width = 20
		}
		b := r.peek(width + 4)
		length := descriptorLength(b, l.zip64, p.crc.Sum32(), actualCompressed, uint64(p.count))
		if length == 0 {
			return fail("ARCHIVE_INTEGRITY", "", "invalid ZIP data descriptor")
		}
		if _, err := r.take(length); err != nil {
			return err
		}
		l.crc = p.crc.Sum32()
		l.compressed = actualCompressed
		l.expanded = uint64(p.count)
	}
	if l.crc != p.crc.Sum32() || l.expanded != uint64(p.count) || l.compressed != actualCompressed {
		return fail("ARCHIVE_INTEGRITY", "", "ZIP CRC or payload sizes disagree")
	}
	return nil
}
func streamEntryOpener(open opener, rawName string, known map[int64]*localZIP) opener {
	return func() (io.ReadCloser, error) {
		root, err := open()
		if err != nil {
			return nil, err
		}
		r := &zipInput{r: bufio.NewReaderSize(root, 65536)}
		for {
			l, _, err := nextLocal(r)
			if err != nil || l == nil {
				_ = root.Close()
				if err == nil {
					err = io.EOF
				}
				return nil, err
			}
			if metadata := known[l.offset]; metadata != nil {
				l.compressed = metadata.compressed
				l.expanded = metadata.expanded
				l.boundKnown = true
			}
			p, err := openLocal(r, l)
			if err != nil {
				_ = root.Close()
				return nil, err
			}
			if string(l.raw) == rawName {
				return &closeGroup{Reader: p, closes: []io.Closer{p.reader, root}}, nil
			}
			if err = finishLocal(r, l, p); err != nil {
				_ = root.Close()
				return nil, err
			}
		}
	}
}
func (e *engine) streamZIP(n *namespace, source io.Reader) error {
	r := &zipInput{r: bufio.NewReaderSize(source, 65536)}
	locals := map[int64]*localZIP{}
	var signature uint32
	for {
		l, sig, err := nextLocal(r)
		if err != nil {
			return archiveError(at(err, n.location()), n.location(), "invalid streaming ZIP local record")
		}
		if l == nil {
			signature = sig
			break
		}
		name, err := zipName(l.raw, l.extra, l.flags)
		if err != nil {
			return at(err, n.location())
		}
		kind := byte('f')
		mode := uint32(0)
		localMode, asi, err := representedZIPMode(0, 0, 0, l.extra)
		if err != nil {
			return at(err, n.location())
		}
		if strings.HasSuffix(name, "/") {
			kind = 'd'
		}
		if asi.present {
			kind, err = checkedZIPKind(n, localMode, name, reportedZIPUnixMode(localMode, l.extra, nil), 0, l.expanded, l.extra)
			if err != nil {
				return err
			}
			mode = uint32(localMode.Perm())
		}
		metadata := n.zipMetadata[string(l.raw)]
		if n.zipMetadata != nil && metadata == nil {
			return fail("ARCHIVE_LAYOUT", n.location(), "local ZIP entry absent from preflight central directory")
		}
		if metadata != nil {
			if metadata.Flags != l.flags || metadata.Method != l.method {
				return fail("ARCHIVE_LAYOUT", n.location(), "ZIP preflight local/central flags or methods disagree")
			}
			name, err = zipName([]byte(metadata.Name), metadata.Extra, metadata.Flags)
			if err != nil {
				return at(err, n.location())
			}
			represented, knownASI, modeErr := representedZIPMode(metadata.Mode(), byte(metadata.CreatorVersion>>8), metadata.ExternalAttrs, metadata.Extra)
			if modeErr != nil {
				return at(modeErr, n.location())
			}
			asi = knownASI
			kind, err = checkedZIPKind(n, represented, name, reportedZIPUnixMode(represented, metadata.Extra, metadata), byte(metadata.CreatorVersion>>8), metadata.UncompressedSize64, metadata.Extra)
			if err != nil {
				return err
			}
			mode = uint32(represented.Perm())
			l.expanded = metadata.UncompressedSize64
			l.compressed = metadata.CompressedSize64
			l.boundKnown = true
		}
		size := int64(l.expanded)
		if l.deferred && l.expanded == 0 && !l.boundKnown {
			size = -1
		}
		if l.expanded > uint64(^uint64(0)>>1) {
			return fail("LIMIT_EXCEEDED", n.location(), "ZIP size exceeds representation limit")
		}
		open := streamEntryOpener(n.opener, string(l.raw), locals)
		ent, err := n.add(name, kind, mode, size, open)
		if err != nil {
			return err
		}
		ent.stored = string(l.raw)
		ent.typeKnown = metadata != nil || asi.present
		l.nameKnown = metadata != nil
		ent.linkExtra = asi.target
		l.entry = ent
		locals[l.offset] = l
		p, err := openLocal(r, l)
		if err != nil {
			return at(err, n.location())
		}
		if err = e.zipPayload(n, ent, p); err != nil {
			_ = p.reader.Close()
			return err
		}
		if err = finishLocal(r, l, p); err != nil {
			return archiveError(at(err, n.location()), n.location(), "invalid ZIP payload/descriptor")
		}
	}
	cdStart := r.offset - 4
	count := uint64(0)
	seen := map[int64]bool{}
	for signature == 0x02014b50 {
		h, err := r.take(42)
		if err != nil {
			return archiveError(err, n.location(), "truncated ZIP central header")
		}
		nl, xl, cl := int(u16(h[24:])), int(u16(h[26:])), int(u16(h[28:]))
		b, err := r.take(nl + xl + cl)
		if err != nil {
			return archiveError(err, n.location(), "truncated ZIP central fields")
		}
		raw, extra := b[:nl], b[nl:nl+xl]
		offset := uint64(u32(h[38:]))
		cs, us := uint64(u32(h[16:])), uint64(u32(h[20:]))
		fields, err := zipExtras(extra)
		if err != nil {
			return at(err, n.location())
		}
		x := fields[1]
		take := func() (uint64, error) {
			if len(x) < 8 {
				return 0, fail("ARCHIVE_INTEGRITY", n.location(), "missing ZIP64 field")
			}
			v := u64(x)
			x = x[8:]
			return v, nil
		}
		if us == 0xffffffff {
			us, err = take()
			if err != nil {
				return err
			}
		}
		if cs == 0xffffffff {
			cs, err = take()
			if err != nil {
				return err
			}
		}
		if offset == 0xffffffff {
			offset, err = take()
			if err != nil {
				return err
			}
		}
		l := locals[int64(offset)]
		if l == nil || seen[int64(offset)] {
			return fail("ARCHIVE_LAYOUT", n.location(), "central/local inventory is not one-to-one")
		}
		seen[int64(offset)] = true
		if err = reconcileZIPExtras(l.extra, extra); err != nil {
			return at(err, n.location())
		}
		if !bytes.Equal(raw, l.raw) || u16(h[4:]) != l.flags || u16(h[6:]) != l.method || u32(h[12:]) != l.crc || cs != l.compressed || us != l.expanded {
			return fail("ARCHIVE_LAYOUT", n.location(), "central and local ZIP records disagree")
		}
		if u16(h[30:]) != 0 {
			return fail("UNSUPPORTED_FORMAT", n.location(), "multi-disk ZIP")
		}
		name, err := zipName(raw, extra, l.flags)
		if err != nil {
			return at(err, n.location())
		}
		localName, err := zipName(l.raw, l.extra, l.flags)
		if err != nil {
			return at(err, n.location())
		}
		if name != localName && !l.nameKnown {
			return fail("UNSUPPORTED_STREAMING", n.location(), "ZIP logical filename is available only in central directory")
		}
		creator := h[1]
		attributes := u32(h[34:])
		mode := uint32(0)
		kind := l.entry.kind
		if creator == 3 || creator == 19 {
			mode = attributes >> 16
			switch mode & 0170000 {
			case 0, 0100000:
			case 0040000:
				if kind != 'd' {
					return fail("ARCHIVE_LAYOUT", n.location(), "directory mode/name mismatch")
				}
			case 0120000:
			default:
				return fail("SPECIAL_FILE", n.entryLocation(name), fmt.Sprintf("unsupported ZIP file type (Unix mode %#o, type bits %#o)", mode, mode&0170000))
			}
		}
		effectiveExtra, err := effectiveZIPExtra(l.extra, extra)
		if err != nil {
			return at(err, n.location())
		}
		represented, centralASI, err := representedZIPMode(unixMode(mode), creator, attributes, effectiveExtra)
		if err != nil {
			return at(err, n.location())
		}
		kind, err = checkedZIPKind(n, represented, name, uint32(mode), creator, l.expanded, effectiveExtra)
		if err != nil {
			return err
		}
		l.entry.mode = uint32(represented.Perm())
		if kind != 'l' && l.entry.discoveryError != nil {
			return l.entry.discoveryError
		}
		if kind == 'l' {
			if l.entry.archiveHint != "" {
				return fail("UNSUPPORTED_STREAMING", n.location(), "ZIP symlink type became available after potential archive-discovery bytes")
			}
			l.entry.kind = 'l'
			if !l.entry.typeKnown && centralASI.present && centralASI.target != nil {
				if l.expanded != 0 {
					return fail("UNSUPPORTED_STREAMING", n.location(), "late ASi symlink metadata cannot be reconciled with an already-consumed payload")
				}
				l.entry.goRaw = l.entry.raw
				l.entry.target = centralASI.target
				l.entry.size = int64(len(centralASI.target))
				l.entry.raw = map[string][]byte{}
				l.entry.blob = map[string][]byte{}
				for _, a := range e.rawAlgs {
					l.entry.raw[a] = sum(a, centralASI.target)
				}
				for _, a := range e.blobAlgs {
					l.entry.blob[a] = object(a, "blob", centralASI.target)
				}
				if err = e.chargeExpanded(uint64(len(centralASI.target)), n.location()); err != nil {
					return err
				}
				l.entry.typeKnown = true
			}
			if e.o.strict && !e.hasScheme("nar") && !l.entry.typeKnown {
				return fail("UNSUPPORTED_STREAMING", n.location(), "streaming ZIP symlink type is available only after its target payload")
			}
			if e.hasScheme("nar") && !l.entry.typeKnown {
				reader, err := l.entry.open()
				if err != nil {
					return err
				}
				target, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
				ce := reader.Close()
				if err != nil {
					return err
				}
				if ce != nil {
					return ce
				}
				if len(target) > 1<<20 {
					return fail("LIMIT_EXCEEDED", n.location(), "symlink target exceeds representation limit")
				}
				l.entry.target = target
			}
		}
		count++
		b, err = r.take(4)
		if err != nil {
			return archiveError(err, n.location(), "missing ZIP end records")
		}
		signature = u32(b)
	}
	cdSize := r.offset - 4 - cdStart
	if count != uint64(len(locals)) {
		return fail("ARCHIVE_LAYOUT", n.location(), "missing central directory entries")
	}
	hasZIP64 := signature == 0x06064b50
	if hasZIP64 {
		zip64Offset := r.offset - 4
		b, err := r.take(8)
		if err != nil {
			return archiveError(err, n.location(), "truncated ZIP64 end")
		}
		size := u64(b)
		if size < 44 {
			return fail("ARCHIVE_LAYOUT", n.location(), "invalid ZIP64 end record")
		}
		b, err = r.take(44)
		if err != nil {
			return archiveError(err, n.location(), "truncated ZIP64 end")
		}
		if u32(b[4:]) != 0 || u32(b[8:]) != 0 || u64(b[12:]) != count || u64(b[20:]) != count || u64(b[28:]) != uint64(cdSize) || u64(b[36:]) != uint64(cdStart) {
			return fail("ARCHIVE_LAYOUT", n.location(), "inconsistent ZIP64 central extent")
		}
		if err = zip64Extensions(r, size-44); err != nil {
			return at(err, n.location())
		}
		loc, err := r.take(20)
		if err != nil || u32(loc) != 0x07064b50 || u32(loc[4:]) != 0 || u64(loc[8:]) != uint64(zip64Offset) || u32(loc[16:]) != 1 {
			return fail("ARCHIVE_LAYOUT", n.location(), "invalid ZIP64 locator")
		}
		b, err = r.take(4)
		if err != nil {
			return archiveError(err, n.location(), "missing ZIP EOCD")
		}
		signature = u32(b)
	}
	if signature != 0x06054b50 {
		return fail("ARCHIVE_LAYOUT", n.location(), "unknown record after ZIP central directory")
	}
	h, err := r.take(18)
	if err != nil {
		return archiveError(err, n.location(), "truncated ZIP EOCD")
	}
	if u16(h) != 0 || u16(h[2:]) != 0 {
		return fail("UNSUPPORTED_FORMAT", n.location(), "multi-disk ZIP")
	}
	if !hasZIP64 && (u16(h[4:]) == 0xffff || u16(h[6:]) == 0xffff || u32(h[8:]) == 0xffffffff || u32(h[12:]) == 0xffffffff) {
		return fail("ARCHIVE_LAYOUT", n.location(), "ZIP64 end chain is required for sentinel fields")
	}
	if u16(h[4:]) != 0xffff && uint64(u16(h[4:])) != count || u16(h[6:]) != 0xffff && uint64(u16(h[6:])) != count || u32(h[8:]) != 0xffffffff && uint64(u32(h[8:])) != uint64(cdSize) || u32(h[12:]) != 0xffffffff && uint64(u32(h[12:])) != uint64(cdStart) {
		return fail("ARCHIVE_LAYOUT", n.location(), "inconsistent ZIP EOCD")
	}
	if _, err = r.take(int(u16(h[16:]))); err != nil {
		return archiveError(err, n.location(), "truncated ZIP comment")
	}
	if _, err = r.r.Peek(1); err != io.EOF {
		return fail("ARCHIVE_LAYOUT", n.location(), "trailing ZIP bytes")
	}
	return n.validate()
}
