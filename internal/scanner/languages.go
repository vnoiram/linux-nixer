package scanner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/mapping"
	"github.com/vnoiram/linux-nixer/internal/model"
)

type LanguageScanner struct{}

func (LanguageScanner) Name() string { return "languages" }

func (LanguageScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	scanNPM(ctx, opts, report)
	scanNodeGlobalPackages(opts, report)
	scanPipx(opts, report)
	scanVenvs(opts, report)
	scanCondaEnvs(opts, report)
	scanVersionManagers(opts, report)
	scanInstalledBins(opts, report)
	scanLanguageProjectHints(opts, report)
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
		text, ok := safeReadFile(opts.Root, pkgJSON)
		if !ok {
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

func scanNodeGlobalPackages(opts Options, report *model.ScanReport) {
	patterns := []struct {
		manager string
		globs   []string
	}{
		{
			manager: "pnpm",
			globs: []string{
				"/home/*/.local/share/pnpm/global/*/node_modules/*/package.json",
				"/home/*/.local/share/pnpm/global/*/.pnpm/*/node_modules/*/package.json",
			},
		},
		{
			manager: "yarn",
			globs: []string{
				"/home/*/.config/yarn/global/node_modules/*/package.json",
				"/home/*/.yarn/global/node_modules/*/package.json",
			},
		},
	}
	for _, group := range patterns {
		for _, pkgJSON := range glob(opts.Root, group.globs...) {
			name, version, ok := readPackageJSON(opts.Root, pkgJSON)
			if !ok {
				continue
			}
			report.Languages.NPM = append(report.Languages.NPM, model.Package{
				Manager:  group.manager,
				Name:     name,
				Version:  version,
				Source:   displayPath(opts.Root, pkgJSON),
				NixNames: mapping.Candidates("npm", name),
				Decision: model.DecisionCandidate,
			})
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

func scanCondaEnvs(opts Options, report *model.ScanReport) {
	for _, env := range glob(opts.Root, "/home/*/miniconda3/envs/*", "/home/*/anaconda3/envs/*", "/home/*/.conda/envs/*") {
		if info, ok := safeStat(opts.Root, env); ok && info.IsDir() {
			report.Languages.Conda = append(report.Languages.Conda, model.Package{
				Manager:  "conda",
				Name:     filepath.Base(env),
				Source:   displayPath(opts.Root, env),
				Decision: model.DecisionMigrationNote,
			})
		}
	}
	for _, cfg := range glob(opts.Root, "/home/*/.condarc") {
		addLanguageProjectItem(opts, report, cfg, "conda configuration")
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
		"mise":   {"/home/*/.local/share/mise", "/home/*/.config/mise"},
	}
	for name, patterns := range tools {
		for _, p := range patterns {
			for _, match := range glob(opts.Root, p) {
				addVersionTool(report, name, displayPath(opts.Root, match))
			}
		}
	}
	for _, marker := range recursiveGlob(opts.Root,
		"/home/*/.tool-versions",
		"/home/*/**/.tool-versions",
		"/home/*/**/.node-version",
		"/home/*/**/.python-version",
		"/home/*/**/.ruby-version",
	) {
		addVersionTool(report, filepath.Base(marker), displayPath(opts.Root, marker))
	}
}

func scanInstalledBins(opts Options, report *model.ScanReport) {
	for _, bin := range glob(opts.Root, "/home/*/.cargo/bin/*") {
		if isRegularExecutable(opts.Root, bin) {
			name := filepath.Base(bin)
			report.Languages.Cargo = append(report.Languages.Cargo, model.Package{Manager: "cargo", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("cargo", name), Decision: model.DecisionCandidate})
		}
	}
	for _, bin := range glob(opts.Root, "/home/*/go/bin/*") {
		if isRegularExecutable(opts.Root, bin) {
			name := filepath.Base(bin)
			report.Languages.Go = append(report.Languages.Go, model.Package{Manager: "go-install", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("go-install", name), Decision: model.DecisionCandidate})
		}
	}
	for _, bin := range glob(opts.Root, "/home/*/.gem/ruby/*/bin/*") {
		if isRegularExecutable(opts.Root, bin) {
			name := filepath.Base(bin)
			report.Languages.Gem = append(report.Languages.Gem, model.Package{Manager: "gem", Name: name, Source: displayPath(opts.Root, bin), NixNames: mapping.Candidates("gem", name), Decision: model.DecisionCandidate})
		}
	}
}

func scanLanguageProjectHints(opts Options, report *model.ScanReport) {
	patterns := []string{
		"/home/*/**/package.json",
		"/home/*/**/package-lock.json",
		"/home/*/**/pnpm-lock.yaml",
		"/home/*/**/yarn.lock",
		"/home/*/**/pyproject.toml",
		"/home/*/**/requirements.txt",
		"/home/*/**/poetry.lock",
		"/home/*/**/Pipfile",
		"/home/*/**/Pipfile.lock",
		"/home/*/**/uv.lock",
		"/home/*/**/environment.yml",
		"/home/*/**/environment.yaml",
		"/home/*/**/conda-lock.yml",
		"/home/*/**/Cargo.toml",
		"/home/*/**/Cargo.lock",
		"/home/*/**/go.mod",
		"/home/*/**/go.sum",
		"/home/*/**/Gemfile",
		"/home/*/**/Gemfile.lock",
		"/srv/**/package.json",
		"/srv/**/pyproject.toml",
		"/srv/**/requirements.txt",
		"/srv/**/poetry.lock",
		"/srv/**/Cargo.toml",
		"/srv/**/go.mod",
		"/srv/**/Gemfile",
	}
	for _, path := range recursiveGlob(opts.Root, patterns...) {
		addLanguageProjectItem(opts, report, path, languageProjectReason(filepath.Base(path)))
	}
}

func addLanguageProjectItem(opts Options, report *model.ScanReport, path, reason string) {
	report.Items = append(report.Items, model.Item{
		Kind:     "language-project",
		Name:     filepath.Base(path),
		Path:     displayPath(opts.Root, path),
		Decision: model.DecisionCandidate,
		Reason:   reason,
	})
}

func addVersionTool(report *model.ScanReport, name, path string) {
	for _, vm := range report.Languages.VMs {
		if vm.Name == name && vm.Path == path {
			return
		}
	}
	report.Languages.VMs = append(report.Languages.VMs, model.VersionTool{Name: name, Path: path})
}

func languageProjectReason(name string) string {
	switch name {
	case "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock":
		return "node dependency or package manager file"
	case "pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock":
		return "python dependency or virtual environment file"
	case "environment.yml", "environment.yaml", "conda-lock.yml":
		return "conda environment file"
	case "Cargo.toml", "Cargo.lock":
		return "rust dependency file"
	case "go.mod", "go.sum":
		return "go module file"
	case "Gemfile", "Gemfile.lock":
		return "ruby dependency file"
	default:
		if strings.HasPrefix(name, "requirements-") && strings.HasSuffix(name, ".txt") {
			return "python dependency or virtual environment file"
		}
		return "language dependency or runtime environment file"
	}
}

func readPackageJSON(root, path string) (string, string, bool) {
	text, ok := safeReadFile(root, path)
	if !ok {
		return "", "", false
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(text, &pkg) != nil || pkg.Name == "" {
		return "", "", false
	}
	return pkg.Name, pkg.Version, true
}

func glob(root string, patterns ...string) []string {
	var out []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(rootPath(root, pattern))
		out = append(out, matches...)
	}
	return out
}

func isRegularExecutable(root, path string) bool {
	info, ok := safeStat(root, path)
	return ok && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

func hasAnySuffix(path string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
