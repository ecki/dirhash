package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"golang.org/x/text/encoding/charmap"
)

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func u64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
func descriptorLength(b []byte, zip64 bool, crc uint32, compressed, expanded uint64) int {
	width := 12
	if zip64 {
		width = 20
	}
	matches := func(d []byte) bool {
		if len(d) < width || u32(d) != crc {
			return false
		}
		if zip64 {
			return u64(d[4:]) == compressed && u64(d[12:]) == expanded
		}
		return uint64(u32(d[4:])) == compressed && uint64(u32(d[8:])) == expanded
	}
	if matches(b) {
		return width
	}
	if len(b) >= 4 && u32(b) == 0x08074b50 && matches(b[4:]) {
		return width + 4
	}
	return 0
}
func zipCodec(method uint16, r io.Reader) (io.ReadCloser, error) {
	switch method {
	case 0:
		return io.NopCloser(r), nil
	case 8:
		return flate.NewReader(r), nil
	case 12:
		return io.NopCloser(bzip2.NewReader(r)), nil
	case 20, 93:
		z, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
		if err != nil {
			return nil, err
		}
		return z.IOReadCloser(), nil
	case 95:
		x, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(x), nil
	default:
		return nil, fail("UNSUPPORTED_METHOD", "", "unsupported ZIP compression method")
	}
}
func supportedMethod(m uint16) bool {
	return m == 0 || m == 8 || m == 12 || m == 20 || m == 93 || m == 95
}
func zipName(raw, extra []byte, flags uint16) (string, error) {
	fields, err := zipExtras(extra)
	if err != nil {
		return "", err
	}
	name := ""
	if flags&0x800 != 0 {
		if !utf8.Valid(raw) {
			return "", fail("INVALID_ENCODING", "", "invalid UTF-8 ZIP filename")
		}
		name = string(raw)
	} else {
		decoded, _ := charmap.CodePage437.NewDecoder().Bytes(raw)
		name = string(decoded)
	}
	if unicode, ok := fields[0x7075]; ok {
		if len(unicode) < 5 || unicode[0] != 1 || u32(unicode[1:]) != crc32.ChecksumIEEE(raw) || !utf8.Valid(unicode[5:]) {
			return "", fail("INVALID_ENCODING", "", "malformed Unicode Path extra field")
		}
		if flags&0x800 != 0 && name != string(unicode[5:]) {
			return "", fail("INVALID_ENCODING", "", "contradictory Unicode ZIP filename")
		}
		name = string(unicode[5:])
	}
	return name, nil
}
func zipExtras(b []byte) (map[uint16][]byte, error) {
	m := map[uint16][]byte{}
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "truncated ZIP extra field")
		}
		id, l := u16(b), int(u16(b[2:]))
		b = b[4:]
		if l > len(b) {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid ZIP extra length")
		}
		if _, ok := m[id]; ok && (id == 1 || id == 0x7075 || id == 0x756e || id == 0x000d || id == 0x5455 || id == 0x000a || id == 0x5855 || id == 0x7855 || id == 0x7875) {
			return nil, fail("ARCHIVE_INTEGRITY", "", "duplicate semantic ZIP extra field")
		}
		m[id] = b[:l]
		b = b[l:]
	}
	return m, nil
}
func zipFlags(flags uint16) error {
	if flags&1 != 0 || flags&0x2040 != 0 {
		return fail("UNSUPPORTED_FORMAT", "", "encrypted ZIP entries are unsupported")
	}
	if flags & ^uint16(0x080e) != 0 {
		return fail("UNSUPPORTED_FORMAT", "", "unsupported ZIP flags")
	}
	return nil
}
func zipKind(mode os.FileMode, name string) (byte, error) {
	if mode&os.ModeIrregular != 0 || mode&os.ModeType != 0 && mode&os.ModeType != os.ModeDir && mode&os.ModeType != os.ModeSymlink {
		return 0, fail("SPECIAL_FILE", "", "unsupported ZIP special entry")
	}

	if strings.HasSuffix(name, "/") || mode.IsDir() {
		if mode&os.ModeSymlink != 0 {
			return 0, fail("INVALID_PATH", "", "symlink has directory-marker suffix")
		}
		return 'd', nil
	}
	if mode&os.ModeSymlink != 0 {
		return 'l', nil
	}
	if mode&os.ModeType != 0 || mode&os.ModeIrregular != 0 {
		return 0, fail("SPECIAL_FILE", "", "unsupported ZIP special entry")
	}
	return 'f', nil
}

func unixModeFromFileMode(mode os.FileMode) uint32 {
	value := uint32(mode.Perm())
	switch {
	case mode.IsDir():
		value |= 0040000
	case mode&os.ModeSymlink != 0:
		value |= 0120000
	case mode&os.ModeNamedPipe != 0:
		value |= 0010000
	case mode&os.ModeSocket != 0:
		value |= 0140000
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		value |= 0020000
	case mode&os.ModeDevice != 0:
		value |= 0060000
	}
	if mode&os.ModeSetuid != 0 {
		value |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 02000
	}
	if mode&os.ModeSticky != 0 {
		value |= 01000
	}
	return value
}

func reportedZIPUnixMode(mode os.FileMode, extra []byte, zf *zip.File) uint32 {
	if zf != nil && (byte(zf.CreatorVersion>>8) == 3 || byte(zf.CreatorVersion>>8) == 19) {
		return uint32(zf.ExternalAttrs >> 16)
	}
	fields, err := zipExtras(extra)
	if err == nil {
		if body := fields[0x756e]; len(body) >= 6 {
			return uint32(u16(body[4:]))
		}
	}
	return unixModeFromFileMode(mode)
}

func checkedZIPKind(n *namespace, mode os.FileMode, name string, unixMode uint32, creator byte, size uint64, extra []byte) (byte, error) {
	fields, extraErr := zipExtras(extra)
	asiPresent := extraErr == nil && len(fields[0x756e]) > 0
	if n != nil && !n.engine.o.strict && (creator == 3 || creator == 19) &&
		unixMode == 0177777 && strings.HasSuffix(name, "/") && size == 0 && !asiPresent {
		n.engine.addWarning("WARN_ZIP_DIRECTORY_MODE", n.entryLocation(name), "accepted malformed empty ZIP directory with Unix mode 0177777")
		return 'd', nil
	}
	typeBits := unixMode & 0170000
	if typeBits != 0 && typeBits != 0100000 && typeBits != 0040000 && typeBits != 0120000 {
		return 0, fail("SPECIAL_FILE", n.entryLocation(name), fmt.Sprintf("unsupported ZIP file type (Unix mode %#o, type bits %#o)", unixMode, typeBits))
	}
	kind, err := zipKind(mode, name)
	if err == nil {
		return kind, nil
	}
	if f, ok := err.(*failure); ok {
		copy := *f
		copy.location = n.entryLocation(name)
		if copy.code == "SPECIAL_FILE" {
			copy.reason = fmt.Sprintf("unsupported ZIP file type (Unix mode %#o, type bits %#o)", unixMode, unixMode&0170000)
		}
		return 0, &copy
	}
	return 0, at(err, n.entryLocation(name))
}

func (e *engine) preflightZIP(n *namespace) error {
	if !n.seekable || n.opener == nil || n.byteLength < 0 {
		return nil
	}
	probe, err := n.opener()
	if err != nil {
		return err
	}
	defer func() { _ = probe.Close() }()
	readerAt, ok := probe.(io.ReaderAt)
	if !ok {
		return nil
	}
	n.zipLocalExtras = map[string][]byte{}
	z, err := accountedZIP(readerAt, n.byteLength, n.location(), n.zipLocalExtras)
	if err != nil {
		return archiveError(err, n.location(), "invalid seekable nested ZIP directory")
	}
	n.zipMetadata = map[string]*zip.File{}
	for _, file := range z.File {
		if _, exists := n.zipMetadata[file.Name]; exists {
			return fail("DUPLICATE_ENTRY", n.location(), "duplicate ZIP source filename")
		}
		n.zipMetadata[file.Name] = file
		file.Extra, err = effectiveZIPExtra(n.zipLocalExtras[file.Name], file.Extra)
		if err != nil {
			return at(err, n.location())
		}
	}
	return nil
}
func (e *engine) seekZIP(n *namespace, _ string, size int64) error {
	f, err := n.opener()
	if err != nil {
		return fail("IO_ERROR", n.location(), "cannot open ZIP")
	}
	e.addCleanup(func() { _ = f.Close() })
	readerAt, ok := f.(io.ReaderAt)
	if !ok {
		return fail("UNSUPPORTED_STREAMING", n.location(), "ZIP input is not seekable")
	}
	if file, ok := f.(*checkedFile); ok {
		sourcePath, before := file.Name(), file.before
		e.checks = append(e.checks, func() error {
			after, err := os.Stat(sourcePath)
			if err != nil || !sameInfo(before, after) {
				return fail("INPUT_CHANGED", n.location(), "seekable ZIP source changed")
			}
			return nil
		})
	}
	localExtras := map[string][]byte{}
	z, err := accountedZIP(readerAt, size, n.location(), localExtras)
	if err != nil {
		return archiveError(err, n.location(), "invalid ZIP central directory")
	}
	for _, m := range []uint16{12, 20, 93, 95} {
		method := m
		z.RegisterDecompressor(method, func(r io.Reader) io.ReadCloser {
			c, err := zipCodec(method, r)
			if err != nil {
				return &errorReadCloser{err}
			}
			return c
		})
	}
	for _, zf := range z.File {
		zf := zf
		if err = zipFlags(zf.Flags); err != nil {
			return at(err, n.location())
		}
		if !supportedMethod(zf.Method) {
			return fail("UNSUPPORTED_METHOD", n.location(), "unsupported ZIP compression method")
		}
		effectiveExtra, err := effectiveZIPExtra(localExtras[zf.Name], zf.Extra)
		if err != nil {
			return at(err, n.location())
		}
		name, err := zipName([]byte(zf.Name), effectiveExtra, zf.Flags)
		if err != nil {
			return at(err, n.location())
		}
		if e.h1 && strings.Contains(zf.Name, "\n") {
			return fail("INVALID_PATH", n.location(), "LF in original ZIP manifest filename")
		}
		mode, asi, err := representedZIPMode(zf.Mode(), byte(zf.CreatorVersion>>8), zf.ExternalAttrs, effectiveExtra)
		if err != nil {
			return at(err, n.location())
		}
		kind, err := checkedZIPKind(n, mode, name, reportedZIPUnixMode(mode, effectiveExtra, zf), byte(zf.CreatorVersion>>8), zf.UncompressedSize64, effectiveExtra)
		if err != nil {
			return err
		}
		if zf.UncompressedSize64 > uint64(^uint64(0)>>1) || zf.CompressedSize64 > uint64(^uint64(0)>>1) {
			return fail("LIMIT_EXCEEDED", n.location(), "ZIP size exceeds representation limit")
		}
		offset, err := zf.DataOffset()
		if err != nil {
			return archiveError(err, n.location(), "invalid ZIP data offset")
		}
		open := func() (io.ReadCloser, error) {
			if err := checkZIPSource(n, f); err != nil {
				return nil, err
			}
			compressed := &zipInput{r: bufio.NewReaderSize(io.NewSectionReader(readerAt, offset, int64(zf.CompressedSize64)), 65536)}
			decoder, err := zipCodec(zf.Method, compressed)
			if err != nil {
				return nil, err
			}
			payload := &verifiedZIP{decoder: decoder, input: compressed, expectedCompressed: zf.CompressedSize64, expectedExpanded: zf.UncompressedSize64, expectedCRC: zf.CRC32, crc: crc32.NewIEEE(), location: n.location()}
			return &checkedZIPPayload{ReadCloser: payload, namespace: n, source: f}, nil
		}
		ent, err := n.add(name, kind, uint32(mode.Perm()), int64(zf.UncompressedSize64), open)
		if err != nil {
			return err
		}
		ent.linkExtra = asi.target
		ent.seekOnly = zf.Method == 0 && ent.kind == 'f'
		// HashZip preserves the bytes held in archive/zip.File.Name, not decoded
		// CP437/Unicode-extra names. Explicit stripping transforms this view.
		if n.top && e.o.strip > 0 {
			raw := strings.Split(strings.TrimSuffix(zf.Name, "/"), "/")
			if e.o.strip < uint64(len(raw)) {
				ent.stored = strings.Join(raw[int(e.o.strip):], "/")
				if strings.HasSuffix(zf.Name, "/") {
					ent.stored += "/"
				}
			}
		} else {
			ent.stored = zf.Name
		}
		compressed := &zipInput{r: bufio.NewReaderSize(io.NewSectionReader(readerAt, offset, int64(zf.CompressedSize64)), 65536)}
		if err = checkZIPSource(n, f); err != nil {
			return err
		}
		decoder, err := zipCodec(zf.Method, compressed)
		if err != nil {
			return archiveError(err, n.location(), "cannot open ZIP codec")
		}
		r := &verifiedZIP{decoder: decoder, input: compressed, expectedCompressed: zf.CompressedSize64, expectedExpanded: zf.UncompressedSize64, expectedCRC: zf.CRC32, crc: crc32.NewIEEE(), location: n.location()}
		err = e.zipPayload(n, ent, r)
		ce := r.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return archiveError(ce, n.location(), "ZIP close failed")
		}
		if err = checkZIPSource(n, f); err != nil {
			return err
		}
	}
	return n.validate()
}

func checkZIPSource(n *namespace, cached io.ReadCloser) error {
	if file, ok := cached.(*checkedFile); ok {
		current, err := file.Stat()
		if err != nil || !sameInfo(file.before, current) {
			return fail("INPUT_CHANGED", n.location(), "ZIP input changed during cached reads")
		}
	}
	return nil
}

type checkedZIPPayload struct {
	io.ReadCloser
	namespace *namespace
	source    io.ReadCloser
}

func (r *checkedZIPPayload) Close() error {
	closeErr := r.ReadCloser.Close()
	if closeErr != nil {
		return closeErr
	}
	return checkZIPSource(r.namespace, r.source)
}

type verifiedZIP struct {
	decoder                              io.ReadCloser
	input                                *zipInput
	expectedCompressed, expectedExpanded uint64
	expectedCRC                          uint32
	crc                                  hashCRC
	count                                uint64
	location                             string
}

func (r *verifiedZIP) Read(b []byte) (int, error) {
	n, err := r.decoder.Read(b)
	if n > 0 {
		_, _ = r.crc.Write(b[:n])
		r.count += uint64(n)
	}
	if r.count > r.expectedExpanded {
		return n, fail("ARCHIVE_INTEGRITY", r.location, "ZIP expanded content exceeds declared size")
	}
	if err == io.EOF && (r.count != r.expectedExpanded || r.crc.Sum32() != r.expectedCRC || uint64(r.input.offset) != r.expectedCompressed) {
		return n, fail("ARCHIVE_INTEGRITY", r.location, "ZIP CRC, expanded size or decoder boundary mismatch")
	}
	return n, err
}
func (r *verifiedZIP) Close() error { return r.decoder.Close() }

type errorReadCloser struct{ err error }

func (r *errorReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *errorReadCloser) Close() error             { return nil }
func (e *engine) zipPayload(n *namespace, ent *entry, r io.Reader) error {
	if ent.kind == 'd' {
		b := make([]byte, 1)
		count, err := io.ReadFull(r, b)
		if count != 0 || err != io.EOF {
			return fail("ARCHIVE_INTEGRITY", n.location(), "ZIP directory marker has content or corrupt stream")
		}
		return nil
	}
	if ent.kind == 'l' {
		if ent.size > 1<<20 {
			return fail("LIMIT_EXCEEDED", n.location(), "symlink target exceeds representation limit")
		}
		target, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		if err != nil {
			return archiveError(err, n.location(), "invalid ZIP symlink payload")
		}
		if len(target) > 1<<20 {
			return fail("LIMIT_EXCEEDED", n.location(), "symlink target exceeds representation limit")
		}
		if ent.linkExtra != nil {
			if len(target) > 0 && !bytes.Equal(target, ent.linkExtra) {
				return fail("ARCHIVE_INTEGRITY", n.location(), "ZIP symlink payload disagrees with ASi target")
			}
			ent.goRaw = map[string][]byte{}
			for _, a := range e.rawAlgs {
				ent.goRaw[a] = sum(a, target)
			}
			target = ent.linkExtra
			ent.size = int64(len(target))
		}
		if n.engine.o.strict && !utf8.Valid(target) {
			return fail("INVALID_ENCODING", n.location(), "invalid ZIP symlink target UTF-8")
		}
		ent.target = target
		return e.payload(n, ent, bytes.NewReader(target), true, false)
	}
	return e.payload(n, ent, r, true, true)
}

// auditZIP independently inventories contiguous local records, then reconciles
// their extents against the central view. It never reads compressed payloads.
func auditZIP(r io.ReaderAt, size int64, location string, localInventory map[string][]byte, eocd int64, centralOffset *int64) error {
	layout := func(reason string) error { return fail("ARCHIVE_LAYOUT", location, reason) }
	read := func(off int64, n int) ([]byte, error) {
		if off < 0 || off > size || int64(n) > size-off {
			return nil, layout("ZIP record outside physical file")
		}
		b := make([]byte, n)
		_, err := r.ReadAt(b, off)
		if err != nil {
			return nil, layout("truncated ZIP record")
		}
		return b, nil
	}
	end, err := read(eocd, 22)
	if err != nil {
		return err
	}
	if u32(end) != 0x06054b50 || eocd+22+int64(u16(end[20:])) != size {
		return layout("ZIP does not end at its EOCD comment")
	}
	if u16(end[4:]) != 0 || u16(end[6:]) != 0 {
		return fail("UNSUPPORTED_FORMAT", location, "multi-disk ZIP")
	}
	count := uint64(u16(end[10:]))
	cdSize, cdOffset := uint64(u32(end[12:])), uint64(u32(end[16:]))
	cdEnd := eocd
	hasZIP64 := false
	if eocd >= 20 {
		locator, err := read(eocd-20, 20)
		if err != nil {
			return err
		}
		hasZIP64 = u32(locator) == 0x07064b50
	}
	if hasZIP64 || count == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff {
		locator, err := read(eocd-20, 20)
		if err != nil {
			return err
		}
		if u32(locator) != 0x07064b50 || u32(locator[4:]) != 0 || u32(locator[16:]) != 1 {
			return layout("invalid ZIP64 locator")
		}
		offset := u64(locator[8:])
		if offset > uint64(size) {
			return layout("invalid ZIP64 offset")
		}
		record, err := read(int64(offset), 56)
		if err != nil {
			return err
		}
		if u32(record) != 0x06064b50 || u64(record[4:]) < 44 || offset > uint64(eocd-20)-12 || u64(record[4:]) != uint64(eocd-20)-offset-12 {
			return layout("unaccounted ZIP64 end records")
		}
		if err = zip64Extensions(io.NewSectionReader(r, int64(offset)+56, int64(u64(record[4:])-44)), u64(record[4:])-44); err != nil {
			return at(err, location)
		}
		if u32(record[16:]) != 0 || u32(record[20:]) != 0 || u64(record[24:]) != u64(record[32:]) {
			return fail("UNSUPPORTED_FORMAT", location, "multi-disk ZIP64")
		}
		count = u64(record[32:])
		cdSize = u64(record[40:])
		cdOffset = u64(record[48:])
		cdEnd = int64(offset)
		if u16(end[8:]) != 0xffff && uint64(u16(end[8:])) != count ||
			u16(end[10:]) != 0xffff && uint64(u16(end[10:])) != count ||
			u32(end[12:]) != 0xffffffff && uint64(u32(end[12:])) != cdSize ||
			u32(end[16:]) != 0xffffffff && uint64(u32(end[16:])) != cdOffset {
			return layout("ZIP64 and ordinary end fields disagree")
		}
	} else if u16(end[8:]) != u16(end[10:]) {
		return layout("ZIP central-directory count mismatch")
	}
	if cdOffset > uint64(size) || cdSize > uint64(size) || cdOffset+cdSize != uint64(cdEnd) || count > cdSize/46 {
		return layout("ZIP central-directory extent/count mismatch")
	}
	*centralOffset = int64(cdOffset)
	// Parse the central extent independently instead of trusting library offsets.
	type central struct {
		offset        int64
		raw, extra    []byte
		flags, method uint16
		crc           uint32
		csize, usize  uint64
	}
	list := make([]central, 0)
	pos := int64(cdOffset)
	for i := uint64(0); i < count; i++ {
		h, err := read(pos, 46)
		if err != nil {
			return err
		}
		if u32(h) != 0x02014b50 {
			return layout("unknown central-directory record")
		}
		nl, xl, cl := int(u16(h[28:])), int(u16(h[30:])), int(u16(h[32:]))
		b, err := read(pos+46, nl+xl+cl)
		if err != nil {
			return err
		}
		c := central{int64(u32(h[42:])), b[:nl], b[nl : nl+xl], u16(h[8:]), u16(h[10:]), u32(h[16:]), uint64(u32(h[20:])), uint64(u32(h[24:]))}
		if u16(h[34:]) != 0 {
			return fail("UNSUPPORTED_FORMAT", location, "split ZIP entry")
		}
		extras, err := zipExtras(c.extra)
		if err != nil {
			return at(err, location)
		}
		x := extras[1]
		take := func() (uint64, bool) {
			if len(x) < 8 {
				return 0, false
			}
			v := u64(x)
			x = x[8:]
			return v, true
		}
		var ok bool
		if c.usize == 0xffffffff {
			c.usize, ok = take()
			if !ok {
				return layout("missing ZIP64 size")
			}
		}
		if c.csize == 0xffffffff {
			c.csize, ok = take()
			if !ok {
				return layout("missing ZIP64 size")
			}
		}
		if c.offset == 0xffffffff {
			v, valid := take()
			if !valid || v > uint64(size) {
				return layout("missing ZIP64 local offset")
			}
			c.offset = int64(v)
		}
		list = append(list, c)
		pos += int64(46 + nl + xl + cl)
	}
	if pos != int64(cdOffset+cdSize) {
		return layout("unaccounted central-directory bytes")
	}
	byOffset := map[int64]central{}
	for _, c := range list {
		if _, ok := byOffset[c.offset]; ok {
			return layout("overlapping local records")
		}
		byOffset[c.offset] = c
	}
	pos = 0
	for range list {
		c, ok := byOffset[pos]
		if !ok {
			return layout("prefix, gap, hidden local entry or overlapping payload")
		}
		h, err := read(pos, 30)
		if err != nil {
			return err
		}
		if u32(h) != 0x04034b50 {
			return layout("missing local ZIP record")
		}
		nl, xl := int(u16(h[26:])), int(u16(h[28:]))
		b, err := read(pos+30, nl+xl)
		if err != nil {
			return err
		}
		if !bytes.Equal(b[:nl], c.raw) || u16(h[6:]) != c.flags || u16(h[8:]) != c.method {
			return layout("local and central name/method/flags disagree")
		}
		localExtra, err := zipExtras(b[nl:])
		if err != nil {
			return at(err, location)
		}
		if _, err = zipName(b[:nl], b[nl:], c.flags); err != nil {
			return at(err, location)
		}
		if err = reconcileZIPExtras(b[nl:], c.extra); err != nil {
			return at(err, location)
		}
		if localInventory != nil {
			localInventory[string(c.raw)] = append([]byte{}, b[nl:]...)
		}
		lc, lu := uint64(u32(h[18:])), uint64(u32(h[22:]))
		lx := localExtra[1]
		if lu == 0xffffffff {
			if len(lx) < 8 {
				return layout("missing local ZIP64 size")
			}
			lu = u64(lx)
			lx = lx[8:]
		}
		if lc == 0xffffffff {
			if len(lx) < 8 {
				return layout("missing local ZIP64 size")
			}
			lc = u64(lx)
		}
		if c.flags&8 == 0 {
			if lc != c.csize || lu != c.usize || u32(h[14:]) != c.crc {
				return layout("local and central sizes/CRC disagree")
			}
		} else if (lc != 0 && lc != c.csize) || (lu != 0 && lu != c.usize) || (u32(h[14:]) != 0 && u32(h[14:]) != c.crc) {
			return layout("invalid ZIP descriptor placeholders")
		}
		start := pos + int64(30+nl+xl)
		if c.csize > uint64(size-start) {
			return layout("ZIP payload extent outside file")
		}
		pos = start + int64(c.csize)
		if c.flags&8 != 0 {
			width := 12
			if c.csize > 0xffffffff || c.usize > 0xffffffff || u32(h[18:]) == 0xffffffff || u32(h[22:]) == 0xffffffff || len(localExtra[1]) >= 16 {
				width = 20
			}
			d, err := read(pos, int(min(int64(width+4), size-pos)))
			if err != nil {
				return err
			}
			length := descriptorLength(d, width == 20, c.crc, c.csize, c.usize)
			if length == 0 {
				return layout("invalid ZIP data descriptor")
			}
			pos += int64(length)
		}
	}
	if pos != int64(cdOffset) {
		return layout("unexplained bytes before central directory")
	}
	return nil
}
