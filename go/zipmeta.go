package main

import (
	"bytes"
	"hash/crc32"
	"os"
	"sort"
)

type asiMetadata struct {
	present  bool
	mode     uint16
	target   []byte
	device   uint32
	uid, gid uint16
}

func effectiveZIPExtra(local, central []byte) ([]byte, error) {
	if err := reconcileZIPExtras(local, central); err != nil {
		return nil, err
	}
	l, _ := zipExtras(local)
	c, _ := zipExtras(central)
	for _, id := range []uint16{0x7075, 0x756e, 0x000d} {
		if _, ok := c[id]; !ok {
			if field, exists := l[id]; exists {
				c[id] = field
			}
		}
	}
	if len(l[0x000d]) > len(c[0x000d]) && len(c[0x000d]) == 12 {
		c[0x000d] = l[0x000d]
	}
	keys := make([]int, 0, len(c))
	for id := range c {
		keys = append(keys, int(id))
	}
	sort.Ints(keys)
	var out []byte
	for _, key := range keys {
		id := uint16(key)
		field := c[id]
		out = append(out, byte(id), byte(id>>8), byte(len(field)), byte(len(field)>>8))
		out = append(out, field...)
	}
	return out, nil
}
func parseASI(extra []byte) (asiMetadata, error) {
	m := asiMetadata{}
	fields, err := zipExtras(extra)
	if err != nil {
		return m, err
	}
	b, ok := fields[0x756e]
	if !ok {
		return m, nil
	}
	if len(b) < 14 || u32(b) != crc32.ChecksumIEEE(b[4:]) {
		return m, fail("ARCHIVE_INTEGRITY", "", "invalid ASi Unix metadata CRC or length")
	}
	m = asiMetadata{present: true, mode: u16(b[4:]), device: u32(b[6:]), uid: u16(b[10:]), gid: u16(b[12:])}
	if m.mode&0170000 == 0120000 {
		if uint64(m.device) != uint64(len(b)-14) {
			return m, fail("ARCHIVE_INTEGRITY", "", "invalid ASi symlink-target length")
		}
		m.target = b[14:]
	} else if len(b) != 14 {
		return m, fail("ARCHIVE_INTEGRITY", "", "unexpected ASi Unix target data")
	}
	return m, nil
}
func unixMode(mode uint32) os.FileMode {
	m := os.FileMode(mode & 0777)
	switch mode & 0170000 {
	case 0, 0100000:
	case 0040000:
		m |= os.ModeDir
	case 0120000:
		m |= os.ModeSymlink
	case 0010000:
		m |= os.ModeNamedPipe
	case 0140000:
		m |= os.ModeSocket
	case 0020000:
		m |= os.ModeDevice | os.ModeCharDevice
	case 0060000:
		m |= os.ModeDevice
	default:
		m |= os.ModeIrregular
	}
	return m
}
func representedZIPMode(base os.FileMode, creator byte, external uint32, extra []byte) (os.FileMode, asiMetadata, error) {
	asi, err := parseASI(extra)
	if err != nil {
		return 0, asi, err
	}
	if !asi.present {
		fields, _ := zipExtras(extra)
		if unix, ok := fields[0x000d]; ok {
			if len(unix) < 12 {
				return 0, asi, fail("ARCHIVE_INTEGRITY", "", "truncated PKWARE Unix metadata")
			}
			if base&os.ModeSymlink != 0 && len(unix) > 12 {
				asi.target = unix[12:]
			}
		}
		return base, asi, nil
	}
	if (creator == 3 || creator == 19) && external>>16 != 0 {
		native := external >> 16
		if native&07777 != uint32(asi.mode)&07777 || (native&0170000 != 0 && uint32(asi.mode)&0170000 != 0 && native&0170000 != uint32(asi.mode)&0170000) {
			return 0, asi, fail("ARCHIVE_LAYOUT", "", "contradictory ZIP Unix permission/type metadata")
		}
	}
	return unixMode(uint32(asi.mode)), asi, nil
}

func reconcileZIPExtras(local, central []byte) error {
	l, err := zipExtras(local)
	if err != nil {
		return err
	}
	c, err := zipExtras(central)
	if err != nil {
		return err
	}
	la, err := parseASI(local)
	if err != nil {
		return err
	}
	ca, err := parseASI(central)
	if err != nil {
		return err
	}
	if la.present && ca.present && (la.mode != ca.mode || la.device != ca.device || la.uid != ca.uid || la.gid != ca.gid || !bytes.Equal(la.target, ca.target)) {
		return fail("ARCHIVE_LAYOUT", "", "contradictory ASi Unix extra fields")
	}
	if a, ok := l[0x7075]; ok {
		if b, also := c[0x7075]; also && !bytes.Equal(a, b) {
			return fail("ARCHIVE_LAYOUT", "", "contradictory Unicode Path extra fields")
		}
	}
	lm, err := zipSemanticFields(l, false)
	if err != nil {
		return err
	}
	cm, err := zipSemanticFields(c, true)
	if err != nil {
		return err
	}
	for k, v := range lm {
		if w, exists := cm[k]; exists && !bytes.Equal(v, w) {
			return fail("ARCHIVE_LAYOUT", "", "contradictory ZIP Unix/timestamp extra metadata")
		}
	}
	return nil
}
func zipSemanticFields(fields map[uint16][]byte, central bool) (map[string][]byte, error) {
	m := map[string][]byte{}
	if b, ok := fields[0x5455]; ok {
		if len(b) < 1 || b[0]&^byte(7) != 0 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid extended timestamp flags")
		}
		flags := b[0]
		b = b[1:]
		for i, key := range []string{"mtime", "atime", "ctime"} {
			if flags&(1<<i) == 0 {
				continue
			}
			if central && i > 0 && len(b) == 0 {
				continue
			}
			if len(b) < 4 {
				return nil, fail("ARCHIVE_INTEGRITY", "", "truncated extended timestamp")
			}
			m["ut-"+key] = b[:4]
			b = b[4:]
		}
		if len(b) != 0 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "unexpected extended timestamp bytes")
		}
	}
	if b, ok := fields[0x000a]; ok {
		times, err := ntfsTimes(b)
		if err != nil {
			return nil, err
		}
		for id, value := range times {
			m["ntfs-"+string(rune(id))] = value
		}
	}
	if b, ok := fields[0x000d]; ok {
		if len(b) < 12 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "truncated PKWARE Unix extra")
		}
		m["pkware-unix-header"] = b[:12]
		if len(b) > 12 {
			m["pkware-unix-data"] = b[12:]
		}
	}
	if b, ok := fields[0x5855]; ok {
		if len(b) != 8 && len(b) != 12 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid legacy Info-ZIP Unix extra")
		}
		m["ux-times"] = b[:8]
		if len(b) == 12 {
			m["ux-ids"] = b[8:]
		}
	}
	if b, ok := fields[0x7855]; ok {
		if len(b) != 0 && len(b) != 4 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid Info-ZIP Unix2 extra")
		}
		if len(b) == 4 {
			m["ux2-ids"] = b
		}
	}
	if b, ok := fields[0x7875]; ok {
		if len(b) < 3 || b[0] != 1 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid Info-ZIP Unix3 extra")
		}
		b = b[1:]
		for _, key := range []string{"uid", "gid"} {
			if len(b) < 1 {
				return nil, fail("ARCHIVE_INTEGRITY", "", "missing Unix3 identifier size")
			}
			size := int(b[0])
			b = b[1:]
			if size == 0 || size > len(b) {
				return nil, fail("ARCHIVE_INTEGRITY", "", "invalid Unix3 identifier size")
			}
			value := b[:size]
			for len(value) > 1 && value[len(value)-1] == 0 {
				value = value[:len(value)-1]
			}
			m["ux3-"+key] = value
			b = b[size:]
		}
		if len(b) != 0 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "unexpected Unix3 extra bytes")
		}
	}
	return m, nil
}
func ntfsTimes(b []byte) (map[uint16][]byte, error) {
	m := map[uint16][]byte{}
	if len(b) < 4 {
		return nil, fail("ARCHIVE_INTEGRITY", "", "truncated NTFS extra field")
	}
	b = b[4:]
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "truncated NTFS attribute")
		}
		id, size := u16(b), int(u16(b[2:]))
		b = b[4:]
		if size > len(b) {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid NTFS attribute size")
		}
		if id == 1 && size != 24 {
			return nil, fail("ARCHIVE_INTEGRITY", "", "invalid NTFS timestamp attribute")
		}
		if previous, exists := m[id]; id == 1 && exists && !bytes.Equal(previous, b[:size]) {
			return nil, fail("ARCHIVE_INTEGRITY", "", "contradictory NTFS timestamp attributes")
		}
		m[id] = b[:size]
		b = b[size:]
	}
	return m, nil
}
