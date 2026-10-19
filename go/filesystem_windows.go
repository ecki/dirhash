package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkDirectoryNames(directory string) error {
	rawDirectory := directory
	if !strings.HasPrefix(rawDirectory, `\\?\`) {
		if strings.HasPrefix(rawDirectory, `\\`) {
			rawDirectory = `\\?\UNC\` + rawDirectory[2:]
		} else {
			rawDirectory = `\\?\` + rawDirectory
		}
	}
	pattern, err := syscall.UTF16PtrFromString(filepath.Join(rawDirectory, "*"))
	if err != nil {
		return fail("INVALID_ENCODING", directory, "invalid filesystem path encoding")
	}
	var data syscall.Win32finddata
	handle, err := syscall.FindFirstFile(pattern, &data)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if err != nil {
		return fail("IO_ERROR", directory, "cannot enumerate raw Windows filenames")
	}
	defer func() { _ = syscall.FindClose(handle) }()
	for {
		for i := 0; i < len(data.FileName) && data.FileName[i] != 0; i++ {
			u := data.FileName[i]
			if u >= 0xd800 && u <= 0xdbff {
				i++
				if i >= len(data.FileName) || data.FileName[i] < 0xdc00 || data.FileName[i] > 0xdfff {
					return fail("INVALID_ENCODING", directory, "unpaired surrogate in Windows filename")
				}
			} else if u >= 0xdc00 && u <= 0xdfff {
				return fail("INVALID_ENCODING", directory, "unpaired surrogate in Windows filename")
			}
		}
		err = syscall.FindNextFile(handle, &data)
		if err == syscall.ERROR_NO_MORE_FILES {
			return nil
		}
		if err != nil {
			return fail("IO_ERROR", directory, "cannot enumerate raw Windows filenames")
		}
	}
}

func privateDirectory(parent, prefix string) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return "", err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	for attempt := 0; attempt < 10; attempt++ {
		var random [16]byte
		if _, err = rand.Read(random[:]); err != nil {
			return "", err
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(random[:]))
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		wide, err := windows.UTF16PtrFromString(absolute)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(wide, &attributes)
		if err == nil {
			return path, nil
		}
		if err != windows.ERROR_ALREADY_EXISTS {
			return "", err
		}
	}
	return "", errors.New("cannot allocate a unique private download directory")
}

func checkLinkEncoding(path string) error {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fail("INVALID_ENCODING", path, "invalid link path encoding")
	}
	handle, err := windows.CreateFile(wide, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fail("IO_ERROR", path, "cannot open raw link metadata")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var buffer [16384]byte
	var count uint32
	if err = windows.DeviceIoControl(handle, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &buffer[0], uint32(len(buffer)), &count, nil); err != nil {
		return fail("IO_ERROR", path, "cannot read raw link metadata")
	}
	if count < 16 {
		return fail("INVALID_ENCODING", path, "truncated reparse metadata")
	}
	start := 16
	switch u32(buffer[:]) {
	case windows.IO_REPARSE_TAG_SYMLINK:
		start = 20
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
	default:
		return fail("SPECIAL_FILE", path, "unsupported reparse point")
	}
	if int(count) < start {
		return fail("INVALID_ENCODING", path, "truncated link metadata")
	}
	for _, field := range []int{8, 12} {
		offset, length := int(u16(buffer[field:])), int(u16(buffer[field+2:]))
		if length%2 != 0 || offset%2 != 0 || offset+length > int(count)-start {
			return fail("INVALID_ENCODING", path, "invalid raw UTF-16 link target extent")
		}
		target := buffer[start+offset : start+offset+length]
		for i := 0; i < len(target); i += 2 {
			u := u16(target[i:])
			if u >= 0xd800 && u <= 0xdbff {
				i += 2
				if i >= len(target) || u16(target[i:]) < 0xdc00 || u16(target[i:]) > 0xdfff {
					return fail("INVALID_ENCODING", path, "unpaired surrogate in link target")
				}
			} else if u >= 0xdc00 && u <= 0xdfff {
				return fail("INVALID_ENCODING", path, "unpaired surrogate in link target")
			}
		}
	}
	return nil
}
