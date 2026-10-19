//go:build !windows

package main

import "os"

func checkDirectoryNames(string) error { return nil }
func checkLinkEncoding(string) error   { return nil }
func privateDirectory(parent, prefix string) (string, error) {
	path, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", err
	}
	if err = os.Chmod(path, 0700); err != nil {
		_ = os.RemoveAll(path)
		return "", err
	}
	return path, nil
}
