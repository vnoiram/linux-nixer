package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type GitScanner struct{}

func (GitScanner) Name() string { return "git-sources" }

func (GitScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	roots := []string{"/opt", "/usr/local/src", "/srv", "/home"}
	for _, include := range opts.Includes {
		roots = append(roots, include)
	}
	for _, base := range roots {
		abs := rootPath(opts.Root, base)
		filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if d.Name() == ".git" {
				src := filepath.Dir(path)
				report.GitSources = append(report.GitSources, inspectGitSource(opts.Root, src))
				return filepath.SkipDir
			}
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		})
	}
	return nil
}

func inspectGitSource(root, path string) model.GitSource {
	source := model.GitSource{Path: displayPath(root, path), Decision: model.DecisionCandidate}
	if config, err := os.ReadFile(filepath.Join(path, ".git", "config")); err == nil {
		for _, line := range strings.Split(string(config), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "url =") {
				source.Remote = strings.TrimSpace(strings.TrimPrefix(line, "url ="))
				break
			}
		}
	}
	if head, err := os.ReadFile(filepath.Join(path, ".git", "HEAD")); err == nil {
		ref := strings.TrimSpace(string(head))
		if strings.HasPrefix(ref, "ref: ") {
			refPath := filepath.Join(path, ".git", strings.TrimPrefix(ref, "ref: "))
			if commit, err := os.ReadFile(refPath); err == nil {
				source.Commit = strings.TrimSpace(string(commit))
			}
		} else {
			source.Commit = ref
		}
	}
	for _, hint := range []string{"flake.nix", "default.nix", "package.nix", "Makefile", "go.mod", "package.json", "pyproject.toml", "Cargo.toml"} {
		if _, err := os.Stat(filepath.Join(path, hint)); err == nil {
			source.Build = append(source.Build, hint)
		}
	}
	return source
}
