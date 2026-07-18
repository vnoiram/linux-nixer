package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type FilesystemDiffScanner struct{}

func (FilesystemDiffScanner) Name() string { return "filesystem-diff" }

func (FilesystemDiffScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	roots := []string{"/etc", "/usr/local", "/opt", "/srv", "/home"}
	if opts.Deep {
		roots = []string{"/"}
	}
	roots = append(roots, opts.Includes...)
	for _, scanRoot := range roots {
		abs := rootPath(opts.Root, scanRoot)
		filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			disp := displayPath(opts.Root, path)
			if d.IsDir() {
				if shouldExclude(disp, opts.Excludes) || shouldSkipDir(d.Name()) || isVirtualOrNoisy(disp) {
					return filepath.SkipDir
				}
				return nil
			}
			if shouldExclude(disp, opts.Excludes) || isVirtualOrNoisy(disp) {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			finding := classifyFile(path, disp, info)
			if finding.Category == "stateful-data" {
				report.StatefulData = append(report.StatefulData, finding)
				return nil
			}
			if finding.Category != "" {
				report.FilesystemDiff = append(report.FilesystemDiff, finding)
			}
			return nil
		})
	}
	return nil
}

func classifyFile(abs, disp string, info os.FileInfo) model.FileFinding {
	f := model.FileFinding{Path: disp, Type: "file", Mode: info.Mode().String(), Size: info.Size(), Decision: model.DecisionCandidate}
	if info.Size() <= 10*1024*1024 {
		if sum, err := sha256File(abs); err == nil {
			f.SHA256 = sum
		}
	}
	head := readHead(abs, 256)
	switch {
	case strings.HasPrefix(string(head), "\x7fELF"):
		f.Category = "executable"
		f.Type = "elf"
		f.Reason = "ELF executable outside explicit package mapping"
	case strings.HasPrefix(string(head), "#!"):
		f.Category = "script"
		f.Type = "script"
		f.Reason = "shebang script"
	case strings.HasSuffix(disp, ".desktop"):
		f.Category = "desktop-entry"
		f.Type = "desktop-entry"
	case strings.HasSuffix(disp, ".service") || strings.HasSuffix(disp, ".timer"):
		f.Category = "service"
		f.Type = "systemd-unit"
	case looksSecret(disp, head):
		f.Category = "secret"
		f.SecretRisk = true
		f.Decision = model.DecisionMigrationNote
		f.Reason = "secret-like file excluded from generated Nix"
	case isStatefulPath(disp):
		f.Category = "stateful-data"
		f.Decision = model.DecisionMigrationNote
	default:
		if strings.HasPrefix(disp, "/etc/") || strings.Contains(disp, "/.config/") {
			f.Category = "config"
		}
	}
	return f
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

func readHead(path string, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, max))
	return b
}

func shouldExclude(path string, excludes []string) bool {
	for _, ex := range excludes {
		if strings.HasPrefix(path, ex) {
			return true
		}
	}
	return false
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "__pycache__", ".cache", "Cache", "target", ".terraform":
		return true
	default:
		return false
	}
}

func isVirtualOrNoisy(path string) bool {
	noisy := []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/cache", "/var/log", "/home/.ecryptfs"}
	for _, p := range noisy {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func isStatefulPath(path string) bool {
	stateful := []string{"/var/lib/postgresql", "/var/lib/mysql", "/var/lib/docker", "/var/lib/containers", "/home/"}
	for _, p := range stateful {
		if strings.HasPrefix(path, p) && !strings.Contains(path, "/.config/") && !strings.Contains(path, "/.local/bin/") {
			return true
		}
	}
	return false
}

func looksSecret(path string, head []byte) bool {
	lower := strings.ToLower(path)
	for _, part := range []string{"id_rsa", "id_ed25519", "private", "secret", "token", "password", ".pem", ".key"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	text := strings.ToLower(string(head))
	return strings.Contains(text, "private key") || strings.Contains(text, "access_token") || strings.Contains(text, "secret_access_key")
}
