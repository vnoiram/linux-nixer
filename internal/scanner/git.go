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
	gitDir := filepath.Join(path, ".git")
	if config, err := os.ReadFile(filepath.Join(gitDir, "config")); err == nil {
		for _, line := range strings.Split(string(config), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "url =") {
				source.Remote = strings.TrimSpace(strings.TrimPrefix(line, "url ="))
				break
			}
		}
	}
	if head, err := os.ReadFile(filepath.Join(gitDir, "HEAD")); err == nil {
		ref := strings.TrimSpace(string(head))
		if strings.HasPrefix(ref, "ref: ") {
			refName := strings.TrimPrefix(ref, "ref: ")
			if strings.HasPrefix(refName, "refs/heads/") {
				source.Build = appendUnique(source.Build, "branch:"+strings.TrimPrefix(refName, "refs/heads/"))
			}
			refPath := filepath.Join(gitDir, refName)
			if commit, err := os.ReadFile(refPath); err == nil {
				source.Commit = strings.TrimSpace(string(commit))
			}
		} else {
			source.Commit = ref
		}
	}
	if _, err := os.Stat(filepath.Join(path, ".gitmodules")); err == nil {
		source.Build = appendUnique(source.Build, "submodules")
	}
	for _, hint := range []string{
		"flake.nix",
		"default.nix",
		"shell.nix",
		"package.nix",
		"Makefile",
		"justfile",
		"Taskfile.yml",
		"go.mod",
		"package.json",
		"pyproject.toml",
		"Cargo.toml",
		"docker-compose.yml",
		"compose.yaml",
	} {
		if _, err := os.Stat(filepath.Join(path, hint)); err == nil {
			source.Build = appendUnique(source.Build, hint)
		}
	}
	source.Dirty = hasGitDirtyMarker(gitDir)
	return source
}

// hasGitDirtyMarker only detects an interrupted/mid-operation git state
// (an unfinished merge/rebase/cherry-pick/revert/bisect, or a stale index
// lock) — not ordinary uncommitted working-tree changes. This scanner
// reads files directly rather than shelling out to git or diffing content
// (consistent with every other scanner here), so it has no way to tell
// whether the working tree differs from HEAD; a repo with normal
// uncommitted edits (the common case) reports Dirty: false.
func hasGitDirtyMarker(gitDir string) bool {
	for _, marker := range []string{
		"index.lock",
		"MERGE_HEAD",
		"CHERRY_PICK_HEAD",
		"REVERT_HEAD",
		"BISECT_LOG",
		"rebase-merge",
		"rebase-apply",
	} {
		if _, err := os.Stat(filepath.Join(gitDir, marker)); err == nil {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
