package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type SecretScanner struct{}

func (SecretScanner) Name() string { return "secrets" }

func (SecretScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	scanSecretPaths(opts, report)
	scanSecretContentHints(opts, report)
	return nil
}

func scanSecretPaths(opts Options, report *model.ScanReport) {
	patterns := []string{
		"/home/*/.ssh/id_*",
		"/root/.ssh/id_*",
		"/home/*/.gnupg/private-keys-v1.d/*.key",
		"/root/.gnupg/private-keys-v1.d/*.key",
		"/home/*/.aws/credentials",
		"/root/.aws/credentials",
		"/home/*/.config/gcloud/application_default_credentials.json",
		"/root/.config/gcloud/application_default_credentials.json",
		"/home/*/.azure/*.json",
		"/root/.azure/*.json",
		"/home/*/.config/gh/hosts.yml",
		"/root/.config/gh/hosts.yml",
		"/home/*/.docker/config.json",
		"/root/.docker/config.json",
		"/home/*/.kube/config",
		"/root/.kube/config",
		"/home/*/.npmrc",
		"/root/.npmrc",
		"/home/*/.pypirc",
		"/root/.pypirc",
		"/home/*/.netrc",
		"/root/.netrc",
		"/home/*/.config/sops/age/keys.txt",
		"/root/.config/sops/age/keys.txt",
		"/home/*/.env",
		"/root/.env",
		"/home/*/.config/environment.d/*.conf",
		"/root/.config/environment.d/*.conf",
		"/etc/ssh/*_key",
		"/etc/ssl/private/*",
		"/etc/letsencrypt/live/*/privkey.pem",
		"/etc/wireguard/*.conf",
		"/etc/NetworkManager/system-connections/*",
	}
	for _, path := range glob(opts.Root, patterns...) {
		addSecretFinding(opts, report, path, secretReason(displayPath(opts.Root, path)))
	}
	for _, store := range glob(opts.Root, "/home/*/.password-store", "/root/.password-store") {
		filepath.WalkDir(store, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".gpg") {
				addSecretFinding(opts, report, path, "password-store encrypted secret")
			}
			return nil
		})
	}
	if opts.Deep {
		for _, path := range recursiveGlob(opts.Root, "/home/*/**/.env", "/srv/**/.env", "/opt/**/.env") {
			addSecretFinding(opts, report, path, "environment file may contain credentials")
		}
	}
}

func scanSecretContentHints(opts Options, report *model.ScanReport) {
	roots := []string{"/home", "/root", "/etc", "/srv", "/opt"}
	if opts.Deep {
		roots = []string{"/"}
	}
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
			if !secretContentCandidate(disp) {
				return nil
			}
			if !opts.Deep && isNestedEnvFile(disp) {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
				return nil
			}
			if looksSecret(disp, readHead(path, 4096)) {
				addSecretFinding(opts, report, path, "secret-like content; raw value omitted")
			}
			return nil
		})
	}
}

func secretContentCandidate(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return true
	case base == "credentials" || base == "config.json" || base == "hosts.yml" || base == ".npmrc" || base == ".pypirc" || base == ".netrc":
		return true
	case strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		return true
	default:
		return false
	}
}

func isNestedEnvFile(path string) bool {
	base := filepath.Base(path)
	if base != ".env" && !strings.HasPrefix(base, ".env.") {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 3 && parts[0] == "home" {
		return false
	}
	if len(parts) == 2 && parts[0] == "root" {
		return false
	}
	return true
}

func addSecretFinding(opts Options, report *model.ScanReport, path, reason string) {
	display := displayPath(opts.Root, path)
	if shouldExclude(display, opts.Excludes) {
		return
	}
	if strings.HasSuffix(display, ".pub") {
		return
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	finding := model.FileFinding{
		Path:       display,
		Type:       "file",
		Mode:       info.Mode().String(),
		Size:       info.Size(),
		Category:   "secret",
		Reason:     filesystemReason(display, reason),
		Decision:   model.DecisionMigrationNote,
		SecretRisk: true,
	}
	if info.Size() <= 10*1024*1024 {
		if sum, err := sha256File(path); err == nil {
			finding.SHA256 = sum
		}
	}
	appendFileFindingUnique(report, finding)
}

func secretReason(path string) string {
	switch {
	case strings.Contains(path, "/.ssh/id_") || strings.HasPrefix(path, "/etc/ssh/"):
		return "ssh private key"
	case strings.Contains(path, "/.gnupg/private-keys-v1.d/"):
		return "gpg private key"
	case strings.Contains(path, "/.aws/credentials"):
		return "aws credentials file"
	case strings.Contains(path, "/.config/gcloud/application_default_credentials.json"):
		return "gcloud application default credentials"
	case strings.Contains(path, "/.azure/"):
		return "azure credentials or token cache"
	case strings.Contains(path, "/.config/gh/hosts.yml"):
		return "github cli host token file"
	case strings.Contains(path, "/.docker/config.json"):
		return "container registry auth file"
	case strings.Contains(path, "/.kube/config"):
		return "kubernetes client config may contain tokens or certificates"
	case strings.Contains(path, "/.npmrc"):
		return "npm auth token file"
	case strings.Contains(path, "/.pypirc"):
		return "python package index credentials"
	case strings.Contains(path, "/.netrc"):
		return "netrc machine credentials"
	case strings.Contains(path, "/.config/sops/age/keys.txt"):
		return "sops age private key"
	case strings.HasPrefix(path, "/etc/ssl/private/"):
		return "system tls private key"
	case strings.Contains(path, "/letsencrypt/") && strings.HasSuffix(path, "/privkey.pem"):
		return "letsencrypt private key"
	case strings.Contains(path, "/wireguard/"):
		return "wireguard config may contain private keys"
	case strings.Contains(path, "/NetworkManager/system-connections/"):
		return "network connection profile may contain credentials"
	case strings.HasSuffix(path, "/.env") || strings.Contains(path, "/.env."):
		return "environment file may contain credentials"
	case strings.Contains(path, "/environment.d/"):
		return "environment.d file may contain credentials"
	default:
		return "secret-like file excluded from generated Nix"
	}
}
