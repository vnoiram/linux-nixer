package baseline

import (
	"os"
	"path/filepath"
	"strings"
)

type Resolution struct {
	Path   string
	Source string
	OK     bool
}

func Resolve(id, cwd string) Resolution {
	if id == "" {
		return Resolution{}
	}
	if info, err := os.Stat(id); err == nil && !info.IsDir() {
		return Resolution{Path: id, Source: "direct-path", OK: true}
	}
	name, ok := NormalizeID(id)
	if !ok {
		name, ok = NormalizeCustomName(id)
	}
	if !ok {
		return Resolution{}
	}
	for _, candidate := range baselineCandidates(name, cwd) {
		if info, err := os.Stat(candidate.path); err == nil && !info.IsDir() {
			return Resolution{Path: candidate.path, Source: candidate.source, OK: true}
		}
	}
	return Resolution{}
}

func NormalizeID(id string) (string, bool) {
	distro, release, ok := strings.Cut(id, ":")
	if !ok || distro == "" || release == "" || strings.Contains(release, "/") || strings.Contains(distro, "/") {
		return "", false
	}
	distro = strings.ToLower(strings.TrimSpace(distro))
	release = strings.ToLower(strings.TrimSpace(release))
	if distro == "" || release == "" {
		return "", false
	}
	return distro + "-" + release + ".json", true
}

func NormalizeCustomName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) || strings.Contains(name, "..") {
		return "", false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return "", false
	}
	if !strings.HasSuffix(name, ".json") {
		name += ".json"
	}
	return name, true
}

type candidate struct {
	path   string
	source string
}

func baselineCandidates(name, cwd string) []candidate {
	var out []candidate
	if cwd != "" {
		out = append(out, candidate{path: filepath.Join(cwd, "baselines", name), source: "project-baselines"})
	}
	if cache := cacheDir(); cache != "" {
		out = append(out, candidate{path: filepath.Join(cache, "baselines", name), source: "user-cache"})
	}
	return out
}

func cacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "linux-nixer")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "linux-nixer")
	}
	return ""
}
