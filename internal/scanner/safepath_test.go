package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeRealPathRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secretOutside := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretOutside, []byte("outside-root-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSymlink(t, root, "/home/alice/escape", secretOutside)

	linkPath := filepath.Join(root, "home", "alice", "escape")
	if _, ok := safeRealPath(root, linkPath); ok {
		t.Fatalf("expected safeRealPath to reject a symlink escaping root")
	}
	if data, ok := safeReadFile(root, linkPath); ok {
		t.Fatalf("expected safeReadFile to refuse reading through an escaping symlink, got: %s", data)
	}
	if _, ok := safeStat(root, linkPath); ok {
		t.Fatalf("expected safeStat to refuse stating through an escaping symlink")
	}
	if head := safeReadHead(root, linkPath, 64); len(head) > 0 {
		t.Fatalf("expected safeReadHead to refuse reading through an escaping symlink, got: %s", head)
	}
	if sum, err := safeSHA256File(root, linkPath); err == nil || sum != "" {
		t.Fatalf("expected safeSHA256File to refuse hashing through an escaping symlink, got %q err=%v", sum, err)
	}
}

func TestSafeRealPathAllowsInRootSymlink(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/lib/os-release", "NAME=Ubuntu\n")
	writeSymlink(t, root, "/etc/os-release", filepath.Join(root, "usr", "lib", "os-release"))

	linkPath := filepath.Join(root, "etc", "os-release")
	data, ok := safeReadFile(root, linkPath)
	if !ok {
		t.Fatal("expected an in-root symlink to resolve successfully")
	}
	if string(data) != "NAME=Ubuntu\n" {
		t.Fatalf("unexpected content: %q", data)
	}
	if head := safeReadHead(root, linkPath, 4); string(head) != "NAME" {
		t.Fatalf("unexpected head: %q", head)
	}
	if sum, err := safeSHA256File(root, linkPath); err != nil || sum == "" {
		t.Fatalf("expected safeSHA256File to hash in-root symlink, sum=%q err=%v", sum, err)
	}
}

func TestSafeRealPathAllowsAnySymlinkWhenRootIsSlash(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(real, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := safeRealPath("/", link); !ok {
		t.Fatal("expected root=/ to allow any symlink, since nothing escapes the whole filesystem")
	}
}

func TestSafeRealPathRejectsMissingPath(t *testing.T) {
	root := t.TempDir()
	if _, ok := safeRealPath(root, filepath.Join(root, "does", "not", "exist")); ok {
		t.Fatal("expected a nonexistent path to be rejected, not silently allowed")
	}
}
