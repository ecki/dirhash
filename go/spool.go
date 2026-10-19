package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

const archiveMemoryLimit int64 = 10_000_000
const archiveBlockSize = 32768

func osTempDirectory() (string, error) {
	parent, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return "", err
	}
	return filepath.Abs(parent)
}

func privateDownloadDirectory() (string, error) {
	parent, err := osTempDirectory()
	if err != nil {
		return "", err
	}
	return privateDirectory(parent, ".dirhash-download-")
}

func (e *engine) privateArchiveDirectory() (string, error) {
	parent, err := osTempDirectory()
	if err != nil {
		return "", err
	}
	if e.selectedRoot != "" {
		relative, err := filepath.Rel(e.selectedRoot, parent)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return "", fail("IO_ERROR", "", "OS temporary directory is inside the selected input root")
		}
	}
	return privateDirectory(parent, ".dirhash-archive-")
}

type archiveMemory struct {
	blocks    [][]byte
	size      int64
	allocated int64
	engine    *engine
}

func (m *archiveMemory) release() {
	m.engine.spoolMu.Lock()
	defer m.engine.spoolMu.Unlock()
	m.engine.spoolMemory -= m.allocated
	m.blocks = nil
	m.allocated = 0
}

func (m *archiveMemory) write(b []byte) bool {
	m.engine.spoolMu.Lock()
	defer m.engine.spoolMu.Unlock()
	if int64(len(b)) > archiveMemoryLimit-m.engine.spoolMemory+m.allocated-m.size {
		return false
	}
	if len(m.blocks) > 0 && len(m.blocks[len(m.blocks)-1]) < archiveBlockSize && m.size+int64(len(b)) > m.allocated {
		return false
	}
	for len(b) > 0 {
		index, offset := int(m.size/archiveBlockSize), int(m.size%archiveBlockSize)
		if index == len(m.blocks) {
			size := min(int64(archiveBlockSize), archiveMemoryLimit-m.engine.spoolMemory)
			m.blocks = append(m.blocks, make([]byte, int(size)))
			m.allocated += size
			m.engine.spoolMemory += size
		}
		n := copy(m.blocks[index][offset:], b)
		m.size += int64(n)
		b = b[n:]
	}
	return true
}

func (m *archiveMemory) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fail("IO_ERROR", "", "negative archive memory offset")
	}
	count := 0
	for len(b) > 0 && offset < m.size {
		index, start := int(offset/archiveBlockSize), int(offset%archiveBlockSize)
		n := copy(b[:min(int64(len(b)), m.size-offset)], m.blocks[index][start:])
		count += n
		offset += int64(n)
		b = b[n:]
	}
	if len(b) > 0 {
		return count, io.EOF
	}
	return count, nil
}

type memoryArchiveReader struct{ *io.SectionReader }

func (*memoryArchiveReader) Close() error { return nil }

func (e *engine) spoolArchive(source io.Reader, expected int64, location string) (opener, int64, error) {
	memory := &archiveMemory{engine: e}
	e.addCleanup(memory.release)
	var file *os.File
	var name string
	var size int64
	spill := func() error {
		dir, err := e.privateArchiveDirectory()
		if err != nil {
			return fail("IO_ERROR", location, "cannot create private nested archive directory")
		}
		e.addCleanup(func() { _ = os.RemoveAll(dir) })
		name = filepath.Join(dir, "archive")
		file, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fail("IO_ERROR", location, "cannot create private nested archive file")
		}
		for offset := int64(0); offset < memory.size; offset += archiveBlockSize {
			block := memory.blocks[offset/archiveBlockSize]
			if _, err := file.Write(block[:min(int64(len(block)), memory.size-offset)]); err != nil {
				return fail("IO_ERROR", location, "cannot write nested archive file")
			}
		}
		memory.release()
		return nil
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	e.spoolMu.Lock()
	availableMemory := archiveMemoryLimit - e.spoolMemory
	e.spoolMu.Unlock()
	if expected > availableMemory {
		if err := spill(); err != nil {
			return nil, 0, err
		}
	}
	buffer := make([]byte, archiveBlockSize)
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			if expected >= 0 && int64(n) > expected-size {
				return nil, 0, fail("ARCHIVE_INTEGRITY", location, "nested archive exceeds declared payload length")
			}
			if file == nil && !memory.write(buffer[:n]) {
				if err := spill(); err != nil {
					return nil, 0, err
				}
			}
			// The parent's accounted payload tee checks its expansion budget
			// before these bytes reach either memory or disk.
			if file != nil {
				if _, err := file.Write(buffer[:n]); err != nil {
					return nil, 0, fail("IO_ERROR", location, "cannot write nested archive file")
				}
			}
			size += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, 0, archiveError(readErr, location, "cannot read nested archive payload")
		}
	}
	if expected >= 0 && size != expected {
		return nil, 0, fail("ARCHIVE_INTEGRITY", location, "nested archive length disagrees with metadata")
	}
	if file == nil {
		return func() (io.ReadCloser, error) {
			return &memoryArchiveReader{io.NewSectionReader(memory, 0, size)}, nil
		}, size, nil
	}
	if err := file.Close(); err != nil {
		return nil, 0, fail("IO_ERROR", location, "cannot close nested archive file")
	}
	info, err := os.Stat(name)
	if err != nil {
		return nil, 0, fail("IO_ERROR", location, "cannot inspect nested archive file")
	}
	return stableOpener(name, info, location), size, nil
}
