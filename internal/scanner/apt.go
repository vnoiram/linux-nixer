package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type AptScanner struct{}

func (AptScanner) Name() string { return "apt" }

func (AptScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	status := rootPath(opts.Root, "/var/lib/dpkg/status")
	f, err := os.Open(status)
	if err != nil {
		return err
	}
	defer f.Close()
	var name, version string
	installed := false
	flush := func() {
		if name != "" && installed {
			report.Packages = append(report.Packages, model.Package{
				Manager:  "apt",
				Name:     name,
				Version:  version,
				NixNames: aptNixCandidates(name),
				Decision: model.DecisionCandidate,
			})
		}
		name, version, installed = "", "", false
	}
	sc := bufio.NewScanner(f)
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
	matches, _ := filepath.Glob(rootPath(opts.Root, "/etc/apt/sources.list.d/*"))
	for _, match := range matches {
		paths = append(paths, displayPath(opts.Root, match))
	}
	for _, path := range paths {
		if !exists(opts.Root, path) {
			continue
		}
		report.Items = append(report.Items, model.Item{
			Kind:     "apt-source",
			Name:     filepath.Base(path),
			Path:     path,
			Decision: model.DecisionCandidate,
			Reason:   "apt repository source",
		})
	}
}

func aptNixCandidates(name string) []string {
	known := map[string]string{
		"build-essential": "gcc",
		"curl":            "curl",
		"git":             "git",
		"jq":              "jq",
		"neovim":          "neovim",
		"nodejs":          "nodejs",
		"python3":         "python3",
		"ripgrep":         "ripgrep",
		"tmux":            "tmux",
		"vim":             "vim",
		"wget":            "wget",
		"zsh":             "zsh",
	}
	if v, ok := known[name]; ok {
		return []string{v}
	}
	return nil
}
