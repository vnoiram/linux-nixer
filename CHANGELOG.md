# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

### Added

- Local release validation script (`scripts/release-check.sh`, `make release-check`) covering changelog, format, vet, test, cross-arch build, and archive smoke test in one command reused by CI.
- Changelog entry check (`scripts/check-changelog.sh`, `make changelog-check`) gating releases on a matching `CHANGELOG.md` version heading.
- Commit and build date metadata embedded in release binaries, surfaced via `linux-nixer version --full`.
- Confirmed containers with a known name and image render as `virtualisation.oci-containers.containers` entries with safe ports and volumes.
- Interactive review filtering (`--pending-only`), a skip-rest-of-section command, and per-section progress indicators.
- Build-time version injection for release binaries.
- Release tag validation and archive smoke tests in the GitHub Actions release workflow.
- Scan JSON validation for schema, decisions, and protected findings.
- Manual migration checklist report for non-automatic migration work.
- Reusable JSON policy files for scan and review rules.
- Command-specific CLI help with examples and flag notes.
- Dedicated secrets scanner for common credential files and token-bearing configs.
- Service detail reporting for systemd units, timers, and cron schedules.
- GUI profile inventory for browser profiles, browser extensions, and editor profiles.
- Expanded stateful data inventory for common databases, queues, monitoring stores, container state, VM images, and `/srv` app data.
- Representative-host integration test running the full scanner registry together, and expanded baseline-diff fixture coverage for content, permission, and new-file changes.
- `baseline fetch` command that builds a baseline manifest from a distro's official Docker/Podman image, so common Ubuntu/Debian releases don't require a local rootfs.
- Structural tests for the Nix package mapping table (normalized keys, non-empty values, alias targets resolve to real entries) plus a documented review checklist for adding new mappings.
- Confirmed cron jobs with a schedule, user, and non-secret-like command render as `services.cron.systemCronJobs` entries; interactive review notes now explain the generation outcome for cron jobs the same way they do for systemd services.
- `policy init --preset <name>` for common migration styles (`workstation`, `server`, `developer-machine`, `minimal-audit`), pre-setting `confirmKinds`/`excludeKinds` for that archetype instead of starting from the generic template.
- `review`/`capture --export-decisions` and `--import-decisions` for repeatable migration sessions and team review: a portable, host-independent record of per-finding decisions keyed by identity (manager+name, path, or kind+path) that can be re-applied to a later scan of the same host or a similar one, taking precedence over policy category rules for the same finding.
- `summary --compare-decisions <path>` for migration progress tracking across repeated scans of the same host: diffs the current scan's decisions against a previously exported decisions snapshot and reports newly decided, changed, regressed-to-pending, and no-longer-present findings.

### Changed

- Interactive review's container and systemd service notes now reflect the exact render-time generation gates (missing name/image, secret-like exec, environment files, unmapped ports/mounts) instead of a blanket "generates when confirmed and safe" claim.
- Removed the `"python"` Nix mapping table (`internal/mapping`): it was an exact, unreachable duplicate of `"pipx"` that no scanner ever called.

### Fixed

- Baseline diff now also detects permission-only changes (e.g. a file gaining or losing its executable bit) when content is unchanged; previously only the content hash was compared.
- `doctor`'s pre-flight file-completeness check now covers all 21 files `render.Project` generates, including `modules/services.nix` and `modules/filesystem-findings.nix` (both imported by the generated flake); previously 5 files were missing from the check, so a corrupted or missing module would only surface as an opaque Nix import error instead of a clear pre-flight failure.

## [0.1.0] - 2026-07-19

### Added

- Initial Go CLI scaffold with scan, review, generate, doctor, and baseline commands.
- Registry-based scanner architecture.
- Scanners for apt, language tools, Git sources, containers, common configuration, and filesystem findings.
- Dedicated package ecosystem scanners for snap, flatpak, AppImage, and Homebrew on Linux.
- NixOS + Home Manager flake rendering.
- Richer generated modules for service, container, and filesystem findings.
- Confirmed-only rendering for system packages, Home Manager packages, and container runtime enables.
- Shared conservative Nix package mapping for apt and common language CLI package managers.
- Baseline ID resolution for project-local and user-cache manifests.
- Development project report generation.
- Baseline manifest creation.
- Non-interactive review decisions for packages, findings, paths, and managers.
- Interactive review mode with safe handling for secret-like and stateful findings.
- VM build validation through `doctor --vm`.
- Optional VM boot script validation through `doctor --boot`.
- Read-only sudo fallback for selected host scan files.
- Dedicated desktop settings scanner and `reports/desktop.md` output.
- Dedicated user shell settings scanner and `reports/user-config.md` output.
- Dedicated system operation settings scanner and `reports/system-config.md` output.
- Dedicated DevOps and project configuration scanners plus `reports/devops-config.md` output.
- Enriched container inspect scanning and `reports/containers.md` output.
- Enriched Git source scanning and `reports/git-sources.md` output.
- Enriched language ecosystem scanning and `reports/languages.md` output.
- Enriched package source scanning and `reports/package-sources.md` output.
- Enriched filesystem migration reporting and `reports/filesystem.md` output.
- Enriched user account scanning and `reports/users.md` output.
- Conservative Nix option rendering for users, shells, selected Home Manager programs, and service hints.
- CI and tag-based release workflow.
