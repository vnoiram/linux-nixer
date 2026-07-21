package baseline

import (
	"context"
	"fmt"
	"strings"
)

// CatalogCheckOptions configures CheckCatalog.
type CatalogCheckOptions struct {
	Backend string
	Runner  CommandRunner
}

// CatalogCheckResult reports whether one catalog entry's pinned digest
// still matches what its tag currently resolves to. Purely informational:
// CheckCatalog never modifies the catalog. A maintainer decides whether to
// bump a drifted entry's digest, per the review checklist in
// DESIGN_AND_ROADMAP.md's "Baseline catalog maintenance" section.
type CatalogCheckResult struct {
	Distro        string
	Release       string
	Image         string
	PinnedDigest  string
	CurrentDigest string `json:",omitempty"`
	Drifted       bool
	// Error is set instead of CurrentDigest/Drifted when the check itself
	// failed (no backend, no network, pull/inspect failure) — Drifted is
	// only meaningful when Error is empty.
	Error string `json:",omitempty"`
}

// CheckCatalog checks every curated catalog entry's pinned digest against
// what its tag currently resolves to, without modifying the catalog.
func CheckCatalog(ctx context.Context, opts CatalogCheckOptions) ([]CatalogCheckResult, error) {
	backend := opts.Backend
	if backend == "" {
		if opts.Runner != nil {
			return nil, fmt.Errorf("backend must be specified when using a custom runner")
		}
		backend = detectHostBackend()
		if backend == "" {
			return nil, fmt.Errorf("no container backend found; install docker or podman, or pass --backend")
		}
	}
	run := func(args ...string) ([]byte, error) {
		return runCommand(ctx, opts.Runner, backend, args...)
	}

	var results []CatalogCheckResult
	for _, entry := range CatalogEntries() {
		result := CatalogCheckResult{
			Distro:       entry.Distro,
			Release:      entry.Release,
			Image:        entry.Image,
			PinnedDigest: entry.Digest,
		}
		qualified := qualifiedImageRef(entry.Image)
		if _, err := run("pull", qualified); err != nil {
			result.Error = fmt.Sprintf("pulling %s: %v", qualified, err)
			results = append(results, result)
			continue
		}
		out, err := run("inspect", "--format={{index .RepoDigests 0}}", qualified)
		if err != nil {
			result.Error = fmt.Sprintf("inspecting %s: %v", qualified, err)
			results = append(results, result)
			continue
		}
		currentDigest, ok := digestFromRepoDigest(strings.TrimSpace(string(out)))
		if !ok {
			result.Error = fmt.Sprintf("could not parse digest from inspect output: %q", strings.TrimSpace(string(out)))
			results = append(results, result)
			continue
		}
		result.CurrentDigest = currentDigest
		result.Drifted = currentDigest != entry.Digest
		results = append(results, result)
	}
	return results, nil
}

// digestFromRepoDigest extracts the "sha256:..." part from a RepoDigests
// entry such as "docker.io/library/ubuntu@sha256:...".
func digestFromRepoDigest(repoDigest string) (string, bool) {
	idx := strings.LastIndex(repoDigest, "@")
	if idx < 0 {
		return "", false
	}
	return repoDigest[idx+1:], true
}
