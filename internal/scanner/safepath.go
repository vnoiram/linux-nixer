// safepath.go guards against a path derived from scanned content (a glob
// match, a WalkDir result, or a path built from file content like a git
// ref) resolving outside the scan's intended root — whether via a
// symlink or via ".." segments in untrusted content. This tool is meant
// to be pointed at --root /mnt/untrusted-image (a mounted/extracted disk
// image from a compromised or adversarial host), so a crafted symlink or
// crafted file content at a scanned path must not be able to redirect a
// read to anywhere on the real host with the result misattributed to the
// in-image path in the report.
//
// Mirrors the bounded-path-check already established in this codebase for
// tar extraction (internal/baseline/fetch.go's safeExtractPath), applied
// here to symlink-following/content-derived paths during a live scan
// instead of to tar entry names during extraction.
package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// safeRealPath resolves path through any symlinks and confirms the fully
// resolved target still stays under root, returning "", false otherwise
// (including if path doesn't exist or can't be resolved). When root is
// "/", this can never fail — nothing escapes the whole filesystem — which
// is what makes load-bearing real-host symlinks like /etc/os-release and
// /etc/resolv.conf keep working with no special-casing needed.
func safeRealPath(root, path string) (string, bool) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = filepath.Clean(root)
	} else {
		resolvedRoot = filepath.Clean(resolvedRoot)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	resolved = filepath.Clean(resolved)
	prefix := resolvedRoot
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	if resolved != resolvedRoot && !strings.HasPrefix(resolved, prefix) {
		return "", false
	}
	return resolved, true
}

// safeStat is a symlink-bounded replacement for os.Stat on a path derived
// from scanned content.
func safeStat(root, path string) (os.FileInfo, bool) {
	resolved, ok := safeRealPath(root, path)
	if !ok {
		return nil, false
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, false
	}
	return info, true
}

// safeReadFile is a symlink-bounded replacement for os.ReadFile on a path
// derived from scanned content.
func safeReadFile(root, path string) ([]byte, bool) {
	resolved, ok := safeRealPath(root, path)
	if !ok {
		return nil, false
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, false
	}
	return data, true
}
