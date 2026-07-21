package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type FilesystemDiffScanner struct{}

func (FilesystemDiffScanner) Name() string { return "filesystem-diff" }

func (FilesystemDiffScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	baselineEntries, baselineLoaded := loadBaselineEntries(opts.BaselineID, report)
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
			if baselineLoaded && !changedFromBaseline(finding, baselineEntries[disp]) {
				return nil
			}
			if finding.Category == "stateful-data" {
				appendStatefulFindingUnique(report, finding)
				return nil
			}
			if finding.Category != "" {
				appendFileFindingUnique(report, finding)
			}
			return nil
		})
	}
	return nil
}

type baselineFile struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   string `json:"mode,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type baselineJSON struct {
	Files []baselineFile `json:"files"`
}

func loadBaselineEntries(id string, report *model.ScanReport) (map[string]baselineFile, bool) {
	if id == "" {
		return nil, false
	}
	f, err := os.Open(id)
	if err != nil {
		message := "baseline manifest path not found; treating scan as classification-only: " + id
		if strings.Contains(id, ":") {
			message = "baseline id could not be resolved; treating scan as classification-only: " + id
		}
		report.Warnings = append(report.Warnings, model.Warning{
			Source:  "filesystem-diff",
			Message: message,
		})
		return nil, false
	}
	defer f.Close()
	var parsed baselineJSON
	if err := json.NewDecoder(f).Decode(&parsed); err != nil {
		report.Warnings = append(report.Warnings, model.Warning{Source: "filesystem-diff", Message: "failed to parse baseline manifest: " + err.Error()})
		return nil, false
	}
	entries := map[string]baselineFile{}
	for _, file := range parsed.Files {
		entries[file.Path] = file
	}
	return entries, true
}

func changedFromBaseline(finding model.FileFinding, base baselineFile) bool {
	if base.Path == "" {
		return true
	}
	if base.SHA256 != "" && finding.SHA256 != "" {
		return base.SHA256 != finding.SHA256 || base.Mode != finding.Mode
	}
	return base.Size != finding.Size || base.Mode != finding.Mode || base.Type != finding.Type
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
		f.Reason = filesystemReason(disp, "ELF executable outside explicit package mapping")
	case strings.HasPrefix(string(head), "#!"):
		f.Category = "script"
		f.Type = "script"
		f.Reason = filesystemReason(disp, "shebang script")
	case strings.HasSuffix(disp, ".desktop"):
		f.Category = "desktop-entry"
		f.Type = "desktop-entry"
		f.Reason = filesystemReason(disp, "desktop entry outside explicit package mapping")
	case strings.HasSuffix(disp, ".service") || strings.HasSuffix(disp, ".timer"):
		f.Category = "service"
		f.Type = "systemd-unit"
		f.Reason = filesystemReason(disp, "systemd unit outside explicit package mapping")
	case looksSecret(disp, head):
		f.Category = "secret"
		f.SecretRisk = true
		f.Decision = model.DecisionMigrationNote
		f.Reason = filesystemReason(disp, "secret-like file excluded from generated Nix")
	case isStatefulPath(disp):
		f.Category = "stateful-data"
		f.Path = normalizeStatefulPath(disp)
		f.Type = "directory"
		f.Size = 0
		f.SHA256 = ""
		f.Decision = model.DecisionMigrationNote
		f.Reason = statefulDataReason(disp)
	default:
		if strings.HasPrefix(disp, "/etc/") || strings.Contains(disp, "/.config/") {
			f.Category = "config"
			f.Reason = filesystemReason(disp, "configuration file outside explicit package mapping")
		}
	}
	return f
}

func filesystemReason(path, base string) string {
	hint := filesystemLocationHint(path)
	if hint == "" {
		return base
	}
	return base + "; " + hint
}

func filesystemLocationHint(path string) string {
	switch {
	case strings.HasPrefix(path, "/opt/"):
		return "under /opt, commonly used for manually installed vendor applications"
	case strings.HasPrefix(path, "/usr/local/bin/") || strings.HasPrefix(path, "/usr/local/sbin/"):
		return "under /usr/local executable path, commonly outside apt package ownership"
	case strings.HasPrefix(path, "/usr/local/"):
		return "under /usr/local, commonly used for local administrator installs"
	case strings.HasPrefix(path, "/srv/"):
		return "under /srv, commonly service or application data"
	case strings.Contains(path, "/.local/bin/"):
		return "under user-local bin, commonly installed outside system package managers"
	case strings.HasPrefix(path, "/home/"):
		return "under a user home directory"
	default:
		return ""
	}
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
	for _, marker := range []string{
		"private key",
		"access_token",
		"refresh_token",
		"secret_access_key",
		"aws_secret_access_key",
		"api_token",
		"api_key",
		"client_secret",
		"password=",
		"token:",
		"auth:",
		"psk=",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func appendFileFindingUnique(report *model.ScanReport, finding model.FileFinding) {
	for _, existing := range report.FilesystemDiff {
		if existing.Path == finding.Path && existing.Category == finding.Category {
			return
		}
	}
	report.FilesystemDiff = append(report.FilesystemDiff, finding)
}

func appendStatefulFindingUnique(report *model.ScanReport, finding model.FileFinding) {
	for _, existing := range report.StatefulData {
		if existing.Path == finding.Path && existing.Category == finding.Category {
			return
		}
	}
	report.StatefulData = append(report.StatefulData, finding)
}
