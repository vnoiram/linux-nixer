package scanner

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/mapping"
	"github.com/vnoiram/linux-nixer/internal/model"
)

type AptScanner struct{}

func (AptScanner) Name() string { return "apt" }

func (AptScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	status, err := readFile(ctx, opts, report, "apt", "/var/lib/dpkg/status")
	if err != nil {
		return err
	}
	manualPackages, autoInstalledPackages, autoInstalledLoaded := aptInstallReasonHints(ctx, opts, report)
	var name, version string
	installed := false
	flush := func() {
		if name != "" && installed {
			source := ""
			switch {
			case manualPackages[name]:
				source = manualPackageSource(opts.Root)
			case autoInstalledPackages[name]:
				source = "dpkg:auto-installed"
			case autoInstalledLoaded:
				source = manualPackageSource(opts.Root)
			}
			report.Packages = append(report.Packages, model.Package{
				Manager:  "apt",
				Name:     name,
				Version:  version,
				Source:   source,
				NixNames: mapping.Candidates("apt", name),
				Decision: model.DecisionCandidate,
			})
		}
		name, version, installed = "", "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			name = value
		case "Version":
			version = value
		case "Status":
			installed = strings.Contains(value, "install ok installed")
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return err
	}
	findAptSources(opts, report)
	return nil
}

func findAptSources(opts Options, report *model.ScanReport) {
	paths := []string{"/etc/apt/sources.list"}
	for _, pattern := range []string{"/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources"} {
		matches, _ := filepath.Glob(rootPath(opts.Root, pattern))
		for _, match := range matches {
			paths = append(paths, displayPath(opts.Root, match))
		}
	}
	for _, path := range paths {
		if !exists(opts.Root, path) {
			continue
		}
		report.Items = append(report.Items, model.Item{
			Kind:     "apt-source",
			Name:     filepath.Base(path),
			Path:     path,
			Source:   aptSourceHint(opts.Root, path),
			Decision: model.DecisionCandidate,
			Reason:   "apt repository source",
		})
	}
	findAptSupportFiles(opts, report)
}

func findAptSupportFiles(opts Options, report *model.ScanReport) {
	groups := []struct {
		kind   string
		reason string
		paths  []string
	}{
		{
			kind:   "apt-keyring",
			reason: "apt repository trust keyring",
			paths:  []string{"/etc/apt/trusted.gpg", "/etc/apt/keyrings/*", "/etc/apt/trusted.gpg.d/*"},
		},
		{
			kind:   "apt-preference",
			reason: "apt package pinning or repository priority",
			paths:  []string{"/etc/apt/preferences", "/etc/apt/preferences.d/*"},
		},
		{
			kind:   "apt-config",
			reason: "apt client configuration",
			paths:  []string{"/etc/apt/apt.conf", "/etc/apt/apt.conf.d/*"},
		},
	}
	for _, group := range groups {
		for _, pattern := range group.paths {
			for _, match := range glob(opts.Root, pattern) {
				if info, err := os.Stat(match); err != nil || info.IsDir() {
					continue
				}
				report.Items = append(report.Items, model.Item{
					Kind:     group.kind,
					Name:     filepath.Base(match),
					Path:     displayPath(opts.Root, match),
					Decision: model.DecisionCandidate,
					Reason:   group.reason,
				})
			}
		}
	}
}

func aptInstallReasonHints(ctx context.Context, opts Options, report *model.ScanReport) (map[string]bool, map[string]bool, bool) {
	if opts.Root == "/" && (opts.Runner != nil || commandAvailable("apt-mark")) {
		out, err := runWithOptions(ctx, opts, "apt-mark", "showmanual")
		if err == nil {
			return packageNameSet(string(out)), nil, false
		}
	}
	autoInstalled, loaded := aptAutoInstalledPackagesFromExtendedStates(opts, report)
	return nil, autoInstalled, loaded
}

func aptAutoInstalledPackagesFromExtendedStates(opts Options, report *model.ScanReport) (map[string]bool, bool) {
	data, err := os.ReadFile(rootPath(opts.Root, "/var/lib/apt/extended_states"))
	if err != nil {
		return nil, false
	}
	autoInstalled := map[string]bool{}
	var name string
	auto := false
	flush := func() {
		if name != "" && auto {
			autoInstalled[name] = true
		}
		name, auto = "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Package":
			name = strings.TrimSpace(value)
		case "Auto-Installed":
			auto = strings.TrimSpace(value) == "1"
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		report.Warnings = append(report.Warnings, model.Warning{Source: "apt", Message: "failed to parse apt extended_states: " + err.Error()})
	}
	return autoInstalled, true
}

func packageNameSet(text string) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name != "" {
			out[name] = true
		}
	}
	return out
}

func manualPackageSource(root string) string {
	if root == "/" {
		return "apt-mark:manual"
	}
	return "dpkg:manual-or-unknown"
}

func aptSourceHint(root, path string) string {
	data, err := os.ReadFile(rootPath(root, path))
	if err != nil {
		return ""
	}
	var hints []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hints = append(hints, line)
		if len(hints) >= 3 {
			break
		}
	}
	return strings.Join(hints, " | ")
}
