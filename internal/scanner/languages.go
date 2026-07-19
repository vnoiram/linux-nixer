package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/mapping"
	"github.com/vnoiram/linux-nixer/internal/model"
)

type LanguageScanner struct{}

func (LanguageScanner) Name() string { return "languages" }

func (LanguageScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	scanNPM(ctx, opts, report)
	scanPipx(opts, report)
	scanVenvs(opts, report)
	scanVersionManagers(opts, report)
	scanInstalledBins(opts, report)
	return nil
}

func scanNPM(ctx context.Context, opts Options, report *model.ScanReport) {
	if opts.Root == "/" && commandAvailable("npm") {
		out, err := runCommand(ctx, opts.Root, "npm", "list", "-g", "--depth=0", "--json")
		if err == nil {
			var parsed struct {
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if json.Unmarshal([]byte(out), &parsed) == nil {
				for name, dep := range parsed.Dependencies {
					report.Languages.NPM = append(report.Languages.NPM, model.Package{Manager: "npm", Name: name, Version: dep.Version, NixNames: mapping.Candidates("npm", name), Decision: model.DecisionCandidate})
				}
			}
		}
	}
	for _, pkgJSON := range glob(opts.Root, "/usr/local/lib/node_modules/*/package.json", "/home/*/.npm-global/lib/node_modules/*/package.json") {
		text, err := os.ReadFile(pkgJSON)
		if err != nil {
			continue
		}
		var pkg struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(text, &pkg) == nil && pkg.Name != "" {
			report.Languages.NPM = append(report.Languages.NPM, model.Package{Manager: "npm", Name: pkg.Name, Version: pkg.Version, Source: displayPath(opts.Root, pkgJSON), NixNames: mapping.Candidates("npm", pkg.Name), Decision: model.DecisionCandidate})
		}
	}
}

func scanPipx(opts Options, report *model.ScanReport) {
	for _, meta := range glob(opts.Root, "/home/*/.local/pipx/venvs/*/pipx_metadata.json") {
		app := filepath.Base(filepath.Dir(meta))
		env := model.PythonEnv{Path: displayPath(opts.Root, filepath.Dir(meta)), Kind: "pipx"}
		env.Packages = append(env.Packages, model.Package{Manager: "pipx", Name: app, NixNames: mapping.Candidates("pipx", app), Decision: model.DecisionCandidate})
		report.Languages.Python = append(report.Languages.Python, env)
	}
}

func scanVenvs(opts Options, report *model.ScanReport) {
	for _, cfg := range glob(opts.Root, "/home/*/*/pyvenv.cfg", "/srv/*/pyvenv.cfg") {
		report.Languages.Python = append(report.Languages.Python, model.PythonEnv{Path: displayPath(opts.Root, filepath.Dir(cfg)), Kind: "venv"})
	}
}

func scanVersionManagers(opts Options, report *model.ScanReport) {
	tools := map[string][]string{
		"asdf":   {"/home/*/.asdf"},
		"nvm":    {"/home/*/.nvm"},
		"fnm":    {"/home/*/.fnm"},
		"volta":  {"/home/*/.volta"},
		"pyenv":  {"/home/*/.pyenv"},
		"rbenv":  {"/home/*/.rbenv"},
		"sdkman": {"/home/*/.sdkman"},
		"conda":  {"/home/*/miniconda3", "/home/*/anaconda3"},
	}
	for name, patterns := range tools {
		for _, p := range patterns {
			for _, match := range glob(opts.Root, p) {
				report.Languages.VMs = append(report.Languages.VMs, model.VersionTool{Name: name, Path: displayPath(opts.Root, match)})
			}
		}
	}
}

func scanInstalledBins(opts Options, report *model.ScanReport) {
	for _, bin := range glob(opts.Root, "/home/*/.cargo/bin/*") {
		if isRegularExecutable(bin) {
			name := filepath.Base(bin)
			report.Languages.Cargo = append(report.Languages.Cargo, model.Package{Manager: "cargo", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("cargo", name), Decision: model.DecisionCandidate})
		}
	}
	for _, bin := range glob(opts.Root, "/home/*/go/bin/*") {
		if isRegularExecutable(bin) {
			name := filepath.Base(bin)
			report.Languages.Go = append(report.Languages.Go, model.Package{Manager: "go-install", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("go-install", name), Decision: model.DecisionCandidate})
		}
	}
	for _, bin := range glob(opts.Root, "/home/*/.gem/ruby/*/bin/*") {
		if isRegularExecutable(bin) {
			name := filepath.Base(bin)
			report.Languages.Gem = append(report.Languages.Gem, model.Package{Manager: "gem", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("gem", name), Decision: model.DecisionCandidate})
		}
	}
}

func glob(root string, patterns ...string) []string {
	var out []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(rootPath(root, pattern))
		out = append(out, matches...)
	}
	return out
}

func isRegularExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

func hasAnySuffix(path string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
