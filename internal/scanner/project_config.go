package scanner

import (
	"context"
	"path/filepath"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type ProjectConfigScanner struct{}

func (ProjectConfigScanner) Name() string { return "project-config" }

func (ProjectConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	patterns := []string{
		"/home/*/**/package.json",
		"/home/*/**/pyproject.toml",
		"/home/*/**/requirements.txt",
		"/home/*/**/go.mod",
		"/home/*/**/Cargo.toml",
		"/home/*/**/flake.nix",
		"/home/*/**/.devcontainer/devcontainer.json",
		"/srv/**/package.json",
		"/srv/**/pyproject.toml",
		"/srv/**/go.mod",
		"/srv/**/Cargo.toml",
		"/srv/**/flake.nix",
	}
	for _, path := range recursiveGlob(opts.Root, patterns...) {
		report.Items = append(report.Items, model.Item{
			Kind:     "dev-project",
			Name:     filepath.Base(path),
			Path:     displayPath(opts.Root, path),
			Decision: model.DecisionCandidate,
			Reason:   "project dependency or development environment file",
		})
	}
	return nil
}
