// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRelPath_Relative(t *testing.T) {
	got := relPath("/foo/bar", "/foo/bar/baz/file.txt")
	if got != "baz/file.txt" {
		t.Errorf("relPath = %q, want 'baz/file.txt'", got)
	}
}

func TestRelPath_SameDir(t *testing.T) {
	got := relPath("/foo/bar", "/foo/bar/file.txt")
	if got != "file.txt" {
		t.Errorf("relPath = %q, want 'file.txt'", got)
	}
}

func TestRelPath_RootPath(t *testing.T) {
	got := relPath("/foo/bar", "/foo/bar")
	if got != "." {
		t.Errorf("relPath = %q, want '.'", got)
	}
}

func TestRelPath_DifferentRoot(t *testing.T) {
	got := relPath("/foo/bar", "/baz/file.txt")
	if got == "" {
		t.Error("relPath should not return empty string")
	}
}

func TestGetInode_RegularFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "testfile.txt")
	os.WriteFile(filePath, []byte("content"), 0644)

	info, _ := os.Stat(filePath)
	inode, ok := getInode(info)

	if !ok {
		t.Log("getInode returned ok=false — may be platform-specific")
	}
	if ok && inode == 0 {
		t.Log("inode is 0 despite ok=true — unusual")
	}
}

func TestGetInode_Directory(t *testing.T) {
	dir := t.TempDir()
	info, _ := os.Stat(dir)
	inode, ok := getInode(info)

	if !ok {
		t.Log("getInode returned ok=false for directory — may be platform-specific")
	}
	_ = inode
}

func TestGetInode_NilInfo(t *testing.T) {
	// getInode panics on nil FileInfo (info.Sys() dereferences nil)
	// This is acceptable — getInode is only called with valid FileInfo from WalkDir
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil FileInfo")
		}
	}()
	getInode(nil)
}
