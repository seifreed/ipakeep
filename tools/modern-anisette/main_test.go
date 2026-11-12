package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteStateIsPrivateAndReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anisette-v4.json")
	state := []byte(`{"identifier":"test"}`)

	if err := writeState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := readState(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(state) {
		t.Fatalf("state round trip mismatch: got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFlattenHeadersRejectsMultipleValues(t *testing.T) {
	_, err := flattenHeaders(http.Header{"X-Apple-I-Md": {"first", "second"}})
	if err == nil {
		t.Fatal("flattenHeaders accepted a multi-valued header")
	}
}

func TestReadStateRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "anisette-v4.json")
	if err := os.WriteFile(target, []byte(`{"identifier":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("readState accepted a symlink")
	}
}

func TestEnsurePrivateDirectoryRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(link); err == nil {
		t.Fatal("ensurePrivateDirectory accepted a symlink")
	}
}
