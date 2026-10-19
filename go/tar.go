package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func tarNumber(b []byte) (int64, error) {
	if len(b) > 0 && b[0]&0x80 != 0 {
		if b[0]&0x40 != 0 {
			return 0, fmt.Errorf("negative TAR extent")
		}
		var n uint64
		for i, c := range b {
			if i == 0 {
				c &= 0x7f
			}
			if n > uint64(^uint64(0)>>1)>>8 {
				return 0, fmt.Errorf("TAR extent overflow")
			}
			n = n<<8 | uint64(c)
		}
		return int64(n), nil
	}
	s := strings.Trim(string(b), " \x00")
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 8, 64)
}
func validTARHeader(b []byte) bool {
	if len(b) != 512 {
		return false
	}
	if bytes.Equal(b, make([]byte, 512)) {
		return true
	}
	want, err := tarNumber(b[148:156])
	if err != nil {
		return false
	}
	var unsigned, signed int64
	for i, c := range b {
		if i >= 148 && i < 156 {
			unsigned += 32
			signed += 32
		} else {
			unsigned += int64(c)
			signed += int64(int8(c))
		}
	}
	return want == unsigned || want == signed
}

// tarAudit observes physical records independently of archive/tar, including
// control records hidden by that reader and the bytes beyond its logical EOF.
type tarAudit struct {
	r                      io.Reader
	strict                 bool
	location               string
	engine                 *engine
	block                  [512]byte
	position               int
	available              int
	delivered              int64
	remaining              int64
	zeros                  int
	ended, sparseExtension bool
	controlType            byte
	control                []byte
	global, local          map[string]string
	sparseExtents          []extent
	captureSparse          bool
	sparseBuffer           []byte
	sparseValues           []int64
	sparseCount            int64
	sparseCursor           int
}

func parsePAXRecords(b []byte) (map[string]string, error) {
	m := map[string]string{}
	for len(b) > 0 {
		space := bytes.IndexByte(b, ' ')
		if space < 1 {
			return nil, fmt.Errorf("invalid PAX length")
		}
		n, err := strconv.Atoi(string(b[:space]))
		if err != nil || n <= space+3 || n > len(b) || b[n-1] != '\n' {
			return nil, fmt.Errorf("invalid PAX record")
		}
		key, value, ok := strings.Cut(string(b[space+1:n-1]), "=")
		if !ok {
			return nil, fmt.Errorf("invalid PAX field")
		}
		m[key] = value
		b = b[n:]
	}
	return m, nil
}
func mergeGlobal(global, update map[string]string) map[string]string {
	if global == nil {
		global = map[string]string{}
	}
	for k, v := range update {
		if v == "" {
			delete(global, k)
		} else {
			global[k] = v
		}
	}
	return global
}
func applyGlobal(h *tar.Header, global map[string]string) {
	if _, local := h.PAXRecords["path"]; !local && global["path"] != "" {
		h.Name = global["path"]
	}
	if _, local := h.PAXRecords["linkpath"]; !local && global["linkpath"] != "" {
		h.Linkname = global["linkpath"]
	}
}

func (a *tarAudit) next() error {
	n, err := io.ReadFull(a.r, a.block[:])
	if err != nil {
		if err == io.EOF && n == 0 {
			if a.strict && (!a.ended || a.zeros < 2) {
				return fail("ARCHIVE_LAYOUT", a.location, "TAR lacks a complete two-block terminator")
			}
			return io.EOF
		}
		return fail("ARCHIVE_INTEGRITY", a.location, "truncated TAR physical block")
	}
	a.position = 0
	a.available = 512
	b := a.block[:]
	if a.sparseExtension {
		a.sparseExtension = b[504] != 0
		more, err := legacySparseExtents(b, 21)
		if err != nil {
			return archiveError(err, a.location, "invalid GNU sparse extension")
		}
		if len(a.sparseExtents)+len(more) > 65536 {
			return fail("LIMIT_EXCEEDED", a.location, "sparse extent count exceeds bounded metadata representation")
		}
		a.sparseExtents = append(a.sparseExtents, more...)
		if a.engine != nil {
			if err := a.engine.chargeEntries(1, a.location); err != nil {
				return err
			}
		}
		return nil
	}
	if a.remaining > 0 {
		if a.captureSparse {
			if a.engine != nil {
				if err := a.engine.chargeEntries(1, a.location); err != nil {
					return err
				}
			}
			if err := a.sparseMapBlock(b); err != nil {
				return err
			}
		}
		logical := min(a.remaining, 512)
		if a.controlType != 0 {
			a.control = append(a.control, b[:logical]...)
		}
		if a.remaining < 512 && a.strict {
			for _, v := range b[a.remaining:] {
				if v != 0 {
					return fail("ARCHIVE_LAYOUT", a.location, "nonzero TAR entry padding")
				}
			}
		}
		a.remaining -= min(a.remaining, 512)
		if a.remaining == 0 && a.controlType != 0 {
			fields, err := parsePAXRecords(a.control)
			if err != nil {
				return fail("ARCHIVE_INTEGRITY", a.location, "invalid PAX control records")
			}
			if a.controlType == 'g' {
				a.global = mergeGlobal(a.global, fields)
			} else {
				a.local = fields
			}
			a.controlType = 0
			a.control = nil
		}
		return nil
	}
	if bytes.Equal(b, make([]byte, 512)) {
		a.zeros++
		if a.zeros >= 2 {
			a.ended = true
		}
		return nil
	}
	if a.ended || a.zeros > 0 {
		if a.strict {
			return fail("ARCHIVE_LAYOUT", a.location, "nonzero bytes after TAR terminator")
		}
		return nil
	}
	if !validTARHeader(b) {
		return fail("ARCHIVE_INTEGRITY", a.location, "invalid TAR header checksum")
	}
	size, err := tarNumber(b[124:136])
	if err != nil || size < 0 {
		return fail("ARCHIVE_INTEGRITY", a.location, "invalid TAR stored size")
	}
	a.remaining = size
	if b[156] == 'S' {
		a.sparseExtension = b[482] != 0
		a.sparseExtents, err = legacySparseExtents(b[386:482], 4)
		if err != nil {
			return archiveError(err, a.location, "invalid GNU sparse map")
		}
	}
	if b[156] == 'x' || b[156] == 'g' || b[156] == 'L' || b[156] == 'K' {
		if size > 1<<20 {
			return fail("LIMIT_EXCEEDED", a.location, "TAR control record exceeds bounded metadata representation")
		}
		if a.engine != nil {
			if err = a.engine.chargeEntries(1, a.location); err != nil {
				return err
			}
		}
		if b[156] == 'x' || b[156] == 'g' {
			if size > 1<<20 {
				return fail("LIMIT_EXCEEDED", a.location, "PAX control record exceeds bounded metadata representation")
			}
			a.controlType = b[156]
			a.control = nil
			if size == 0 {
				if a.controlType == 'x' {
					a.local = map[string]string{}
				}
				a.controlType = 0
			}
		}
	} else {
		if b[156] != 'S' {
			a.sparseExtents = nil
		}
		a.captureSparse = a.local["GNU.sparse.major"] == "1"
		a.sparseBuffer = nil
		a.sparseValues = nil
		a.sparseCount = -1
		a.sparseCursor = 0
		effectiveSize := a.global["size"]
		if value, ok := a.local["size"]; ok {
			effectiveSize = value
		}
		if effectiveSize != "" && (b[156] == 0 || b[156] == '0' || b[156] == 'S') {
			size, err = strconv.ParseInt(effectiveSize, 10, 64)
			if err != nil || size < 0 {
				return fail("ARCHIVE_INTEGRITY", a.location, "invalid effective PAX size")
			}
			a.remaining = size
			for i := 124; i < 136; i++ {
				b[i] = 0
			}
			n := uint64(size)
			for i := 135; i >= 124; i-- {
				b[i] = byte(n)
				n >>= 8
			}
			b[124] |= 0x80
			for i := 148; i < 156; i++ {
				b[i] = ' '
			}
			checksum := 0
			for _, v := range b {
				checksum += int(v)
			}
			copy(b[148:156], fmt.Sprintf("%06o\x00 ", checksum))
		}
		a.local = nil
	}
	return nil
}
func (a *tarAudit) Read(b []byte) (int, error) {
	if a.position == a.available {
		if err := a.next(); err != nil {
			return 0, err
		}
	}
	n := copy(b, a.block[a.position:a.available])
	a.position += n
	a.delivered += int64(n)
	return n, nil
}

func seekRangeOpener(open opener, offset, size int64) opener {
	return func() (io.ReadCloser, error) {
		root, err := open()
		if err != nil {
			return nil, err
		}
		readerAt, ok := root.(io.ReaderAt)
		if !ok {
			_ = root.Close()
			return nil, fail("UNSUPPORTED_STREAMING", "", "archive source is no longer seekable")
		}
		return &seekRange{SectionReader: io.NewSectionReader(readerAt, offset, size), close: root}, nil
	}
}

type seekRange struct {
	*io.SectionReader
	close io.Closer
}

func (r *seekRange) Close() error { return r.close.Close() }

type closeGroup struct {
	io.Reader
	closes []io.Closer
}

func (r *closeGroup) Close() error {
	var first error
	for _, c := range r.closes {
		if e := c.Close(); e != nil && first == nil {
			first = e
		}
	}
	return first
}
func tarReader(open opener, typ string) (*tar.Reader, io.Closer, error) {
	r, err := open()
	if err != nil {
		return nil, nil, err
	}
	var source io.Reader = r
	closes := []io.Closer{r}
	if typ == "tar.gz" {
		gz, err := gzip.NewReader(r)
		if err != nil {
			_ = r.Close()
			return nil, nil, err
		}
		source = gz
		closes = append([]io.Closer{gz}, closes...)
	}
	audit := &tarAudit{r: source}
	return tar.NewReader(audit), &closeGroup{Reader: source, closes: closes}, nil
}
func tarEntryOpener(open opener, typ, stored string) opener {
	return func() (io.ReadCloser, error) {
		tr, close, err := tarReader(open, typ)
		if err != nil {
			return nil, err
		}
		var global map[string]string
		for {
			h, err := tr.Next()
			if err != nil {
				_ = close.Close()
				return nil, err
			}
			if h.Typeflag == tar.TypeXGlobalHeader {
				global = mergeGlobal(global, h.PAXRecords)
				continue
			}
			applyGlobal(h, global)
			if h.Name == stored {
				return &closeGroup{Reader: tr, closes: []io.Closer{close}}, nil
			}
		}
	}
}
func (e *engine) readTAR(n *namespace, source io.Reader) error {
	seekable := n.inputType == "tar" && n.opener != nil && (n.top || n.seekable)
	br := bufio.NewReaderSize(source, 65536)
	var raw io.Reader = br
	var gz *gzip.Reader
	if n.inputType == "tar.gz" {
		var err error
		gz, err = gzip.NewReader(br)
		if err != nil {
			return fail("ARCHIVE_INTEGRITY", n.location(), "invalid gzip header")
		}
		defer func() { _ = gz.Close() }()
		if e.o.strict {
			gz.Multistream(false)
		}
		raw = gz
	}
	audit := &tarAudit{r: raw, strict: e.o.strict, location: n.location(), engine: e}
	tr := tar.NewReader(audit)
	var global map[string]string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return archiveError(err, n.location(), "invalid TAR records")
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			global = mergeGlobal(global, h.PAXRecords)
			continue
		}
		applyGlobal(h, global)
		var kind byte
		switch h.Typeflag {
		case tar.TypeReg, byte(0), tar.TypeGNUSparse:
			kind = 'f'
		case tar.TypeDir:
			kind = 'd'
		case tar.TypeSymlink:
			kind = 'l'
		case tar.TypeLink:
			kind = 'h'
		default:
			return fail("SPECIAL_FILE", n.location(), "unsupported TAR entry type")
		}
		stored := h.Name
		open := tarEntryOpener(n.opener, n.inputType, stored)
		size := h.Size
		if kind == 'd' || kind == 'h' {
			size = 0
		}
		if kind == 'l' {
			size = int64(len(h.Linkname))
		}
		sparse := h.Typeflag == tar.TypeGNUSparse
		for key := range h.PAXRecords {
			if strings.HasPrefix(key, "GNU.sparse.") {
				sparse = true
			}
		}
		seekOnly := seekable && kind == 'f'
		if seekOnly {
			if sparse {
				extents := audit.sparseExtents
				if value, exists := h.PAXRecords["GNU.sparse.map"]; exists {
					extents, err = paxSparseExtents(value)
					if err != nil {
						return archiveError(err, n.location(), "invalid sparse map")
					}
				}
				extents, err = finalizeExtents(extents, size)
				if err != nil {
					return at(err, n.location())
				}
				open = sparseRangeOpener(n.opener, audit.delivered, size, extents)
			} else {
				open = seekRangeOpener(n.opener, audit.delivered, size)
			}
		}
		ent, err := n.add(stored, kind, uint32(h.Mode), size, open)
		if err != nil {
			return err
		}
		ent.seekOnly = seekOnly
		switch kind {
		case 'd':
			if h.Size != 0 {
				return fail("ARCHIVE_INTEGRITY", n.location(), "directory has nonempty payload")
			}
		case 'l':
			if e.o.strict && !validUTF8(h.Linkname) {
				return fail("INVALID_ENCODING", n.location(), "invalid UTF-8 link target")
			}
			ent.target = []byte(h.Linkname)
			if err = e.payload(n, ent, bytes.NewReader(ent.target), true, false); err != nil {
				return err
			}
		case 'h':
			target, err := validPath(h.Linkname, false)
			if err != nil {
				return at(fail("INVALID_HARDLINK", "", "invalid hard-link target"), n.location())
			}
			ent.hardlink = target
		default:
			if err = e.tarPayload(n, ent, tr); err != nil {
				return err
			}
		}
	}
	// archive/tar intentionally stops at its end marker; draining our observer
	// establishes physical EOF and validates gzip CRC/ISIZE as well.
	remaining := io.Reader(audit)
	if !e.o.strict {
		remaining = raw
	}
	if _, err := io.CopyBuffer(io.Discard, remaining, make([]byte, 32768)); err != nil {
		return archiveError(err, n.location(), "invalid TAR termination")
	}
	if e.o.strict && (!audit.ended || audit.zeros < 2) {
		return fail("ARCHIVE_LAYOUT", n.location(), "incomplete TAR end marker")
	}
	if gz != nil && e.o.strict {
		if _, err := br.Peek(1); err != io.EOF {
			return fail("ARCHIVE_LAYOUT", n.location(), "additional gzip members or trailing bytes")
		}
	}
	return n.validate()
}
func archiveError(err error, location, reason string) error {
	if _, ok := err.(*failure); ok {
		return err
	}
	return fail("ARCHIVE_INTEGRITY", location, reason+": "+err.Error())
}
