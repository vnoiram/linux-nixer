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
	roots = append(roots, opts.Includes...)
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
	if config, ok := safeReadFile(root, filepath.Join(gitDir, "config")); ok {
		for _, line := range strings.Split(string(config), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "url =") {
				source.Remote = redactRemoteCredentials(strings.TrimSpace(strings.TrimPrefix(line, "url =")))
				break
			}
		}
	}
	if head, ok := safeReadFile(root, filepath.Join(gitDir, "HEAD")); ok {
		ref := strings.TrimSpace(string(head))
		if strings.HasPrefix(ref, "ref: ") {
			refName := strings.TrimPrefix(ref, "ref: ")
			if strings.HasPrefix(refName, "refs/heads/") {
				source.Build = appendUnique(source.Build, "branch:"+strings.TrimPrefix(refName, "refs/heads/"))
			}
			refPath := filepath.Join(gitDir, refName)
			// HEAD's content is untrusted (scanned from the target
			// filesystem): a crafted "ref: ../../../../etc/shadow"-style
			// value would otherwise escape gitDir/root via plain ".."
			// collapsing, no symlink required at all.
			if commit, ok := safeReadFile(root, refPath); ok {
				source.Commit = strings.TrimSpace(string(commit))
			}
		} else {
			source.Commit = ref
		}
	}
	if _, ok := safeStat(root, filepath.Join(path, ".gitmodules")); ok {
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
		if _, ok := safeStat(root, filepath.Join(path, hint)); ok {
			source.Build = appendUnique(source.Build, hint)
		}
	}
	source.Dirty = hasGitDirtyMarker(root, gitDir)
	return source
}

// hasGitDirtyMarker only detects an interrupted/mid-operation git state
// (an unfinished merge/rebase/cherry-pick/revert/bisect, or a stale index
// lock) — not ordinary uncommitted working-tree changes. This scanner
// reads files directly rather than shelling out to git or diffing content
// (consistent with every other scanner here), so it has no way to tell
// whether the working tree differs from HEAD; a repo with normal
// uncommitted edits (the common case) reports Dirty: false.
// redactRemoteCredentials strips embedded userinfo credentials from a git
// remote URL (e.g. "https://oauth2:ghp_xxx@github.com/org/repo.git", a
// common pattern for private-repo access) before it's stored in the scan
// report and rendered into reports/reports-annotations verbatim. SSH
// shorthand remotes (e.g. "git@github.com:org/repo.git") have no "://"
// and rely on key-based auth, not a password, so they're left alone.
func redactRemoteCredentials(remote string) string {
	schemeIdx := strings.Index(remote, "://")
	if schemeIdx < 0 {
		return remote
	}
	rest := remote[schemeIdx+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return remote
	}
	if slash := strings.Index(rest, "/"); slash >= 0 && slash < at {
		return remote
	}
	return remote[:schemeIdx+3] + "<redacted>" + rest[at:]
}

func hasGitDirtyMarker(root, gitDir string) bool {
	for _, marker := range []string{
		"index.lock",
		"MERGE_HEAD",
		"CHERRY_PICK_HEAD",
		"REVERT_HEAD",
		"BISECT_LOG",
		"rebase-merge",
		"rebase-apply",
	} {
		if _, ok := safeStat(root, filepath.Join(gitDir, marker)); ok {
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
