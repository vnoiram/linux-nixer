package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manifest struct {
	SchemaVersion string      `json:"schemaVersion"`
	Distro        string      `json:"distro"`
	Release       string      `json:"release"`
	GeneratedAt   time.Time   `json:"generatedAt"`
	Source        string      `json:"source,omitempty"`
	Files         []FileEntry `json:"files"`
	Checksum      string      `json:"checksum,omitempty"`
}

type FileEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   string `json:"mode,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

func Create(ctx context.Context, distro, release, root string) (*Manifest, error) {
	_ = ctx
	m := &Manifest{
		SchemaVersion: "linux-nixer.baseline.v1",
		Distro:        distro,
		Release:       release,
		GeneratedAt:   time.Now().UTC(),
		Source:        "local-rootfs:" + root,
	}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return nil
		}
		disp := "/" + filepath.ToSlash(rel)
		if skipBaselinePath(disp, d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		entry := FileEntry{Path: disp, Type: typeOf(info), Mode: info.Mode().String(), Size: info.Size()}
		if info.Mode().IsRegular() && info.Size() <= 10*1024*1024 {
			if sum, err := sha256File(path); err == nil {
				entry.SHA256 = sum
			}
		}
		m.Files = append(m.Files, entry)
		return nil
	}); err != nil {
		return nil, err
	}
	m.Checksum = manifestChecksum(m.Files)
	return m, nil
}

func typeOf(info os.FileInfo) string {
	switch {
	case info.IsDir():
		return "dir"
	case info.Mode().IsRegular():
		return "file"
	case info.Mode()&os.ModeSymlink != 0:
		return "symlink"
	default:
		return "other"
	}
}

func skipBaselinePath(path string, d os.DirEntry) bool {
	skip := []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache", "/var/log"}
	for _, s := range skip {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}
	name := d.Name()
	return name == ".git" || name == "node_modules" || name == "__pycache__"
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func manifestChecksum(files []FileEntry) string {
	h := sha256.New()
	for _, f := range files {
		io.WriteString(h, f.Path)
		io.WriteString(h, f.Type)
		io.WriteString(h, f.Mode)
		io.WriteString(h, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}
