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
- `reports/migration-annotations.nix`: a structured, standalone Nix attribute set tracing every confirmed container/systemd service/cron job to the Nix option it renders as, or why not — not imported into the NixOS configuration, purely a queryable trace (`nix eval --file reports/migration-annotations.nix`).
- `baseline import --tar <path>` builds a baseline manifest from an already-downloaded flat rootfs tar (an official distro base-rootfs tarball, or a carried-over `docker export` tar), for fully offline use with neither a container backend nor network access; auto-decompresses gzip and supports `--tar -` for stdin.
- `scan`/`capture --plugin PATH` runs an external executable as an extra scanner: a documented JSON protocol on stdin/stdout (reusing the existing `scan.json`/`reviewed.json` schema as the output contract) rather than dynamic Go plugin loading or a published Go module, so a plugin can be written in any language. Plugin-contributed `items`/`warnings` are merged; plugins always run as the current user, never with `--sudo` elevation, and are bounded by a 30s timeout. See "Plugin scanners" in `DESIGN_AND_ROADMAP.md`.
- Policy files can set default `--plugin` paths via a `plugins` list field, merged with CLI `--plugin` flags the same way as `includePaths`/`excludePaths`, consistent with every other scan option already being policy-configurable.
- `scan`/`capture --plugin-timeout DURATION` overrides the default 30s timeout for plugin scanner invocations.
- `plugin check --plugin PATH` invokes a single plugin once with a synthetic request and validates its JSON output with the same structural checks `validate` runs on `scan.json`/`reviewed.json`, catching a broken plugin before a real `scan`/`capture`.
- Plugin scanners now also merge `packages`/`services`/`containers` from a plugin's output, in addition to `items`/`warnings`; these flow through review and Nix generation exactly like built-in scanner output, so a plugin that knows this tool's per-domain conventions can contribute directly instead of only via the general-purpose `items` type.
- `reports/migration-annotations.nix` now also covers confirmed packages (both `environment.systemPackages` and Home Manager `home.packages`) and every scanned user, in addition to the existing containers/systemd services/cron jobs.
- `validate --decisions decisions.json --policy policy.json` checks a decisions file for consistency with a policy's kind vocabulary, warning about stale entries (recorded decision disagrees with what the current policy would now produce for that kind) or unresolvable ones (unrecognized domain, or a key with no recoverable kind).
- CI job (`nix-verify`) installs a real Nix toolchain and runs `capture`/`doctor --vm` against it, validating that the generated flake/modules are real, buildable Nix — the first time any `nix`-touching functionality in this project has run against real `nix` rather than only being designed against it.
- `baseline list` prints the curated catalog of distro/release pairs `baseline fetch` knows how to pull (`internal/baseline/catalog.go`); `baseline fetch` now validates `--distro`/`--release` against this catalog and rejects an unsupported combination with a clear message before attempting a `docker pull`, instead of building the image reference as a bare `distro:release` concatenation and failing opaquely inside the pull.
- Documented a compatibility policy for the plugin JSON protocol in DESIGN_AND_ROADMAP.md (what's additive vs. what requires a new `schemaVersion`), plus regression tests pinning the `linux-nixer.plugin-request.v1`/`linux-nixer.scan.v1` version constants so a future change to either is a deliberate decision, not an accidental edit.
- `reports/migration-annotations.nix` now includes an entry for every package/container/systemd service/cron job regardless of decision, not just confirmed ones; a non-confirmed entry's note explains the decision itself (`excluded`, `todo`, `migration-note`, or a still-pending `candidate`) instead of a structural/safety reason, so the file answers "why isn't this in Nix" for everything, not only "why is this in Nix."
- `baseline fetch --offline` builds a manifest from a real, pre-built fixture bundled directly into the binary (`internal/baseline/baselines_data/`, embedded via `internal/baseline/embedded.go`) for every catalog distro/release, so a fully offline host with neither Docker/Podman nor network access can still get a real baseline for a common release.

### Changed

- Interactive review's container and systemd service notes now reflect the exact render-time generation gates (missing name/image, secret-like exec, environment files, unmapped ports/mounts) instead of a blanket "generates when confirmed and safe" claim.
- Removed the `"python"` Nix mapping table (`internal/mapping`): it was an exact, unreachable duplicate of `"pipx"` that no scanner ever called.
- `doctor --boot` now scans captured VM console output for known boot-failure signatures (kernel panic, emergency mode, unable to mount root fs, etc.) regardless of how the boot script exited, instead of treating any timeout as success unconditionally; a hung or crashed VM that happens to still be running when the timeout fires is now caught instead of silently passing.
- `nix-verify` CI now attempts `doctor --boot` (with a longer `--timeout`) instead of skipping it: this project never sets `virtualisation.qemu.forceAccel`, so the generated VM script uses nixpkgs' default KVM-with-TCG-fallback accelerator rather than hard-requiring `/dev/kvm` as the previous CI comment assumed, so a GitHub-hosted runner without `/dev/kvm` can still attempt a real (software-emulated) boot instead of the step being skipped outright.
- `baseline fetch` now pulls each catalog entry's exact verified image digest (`CatalogDigest`, `internal/baseline/catalog.go`), not just its floating tag, so fetched content can't silently drift as a tag like `ubuntu:24.04` gets rebuilt over time — the manifest's `source` field records the pinned `image@sha256:...` reference actually pulled. `baseline list` now also prints each entry's digest.
- Git source `dirty`/checklist wording now says what's actually detected (an interrupted merge/rebase/cherry-pick/revert/bisect, or a stale index lock) instead of implying general uncommitted-changes detection, which this scanner has never done (it reads files directly rather than diffing against HEAD).
- `baseline list --json` writes machine-readable JSON (one object per catalog entry: distro, release, image, digest), matching the `--json` convention already used by `summary`/`validate`/`plugin check`.
- Baseline catalog and offline bundled manifests now cover Fedora 40 and 41, in addition to the existing Ubuntu/Debian releases.
- `baseline check` reports whether any catalog entry's pinned digest has drifted from what its tag currently resolves to, without ever modifying the catalog — purely informational by default, with `--fail-on-drift` for optional CI/periodic use.

### Fixed

- Baseline diff now also detects permission-only changes (e.g. a file gaining or losing its executable bit) when content is unchanged; previously only the content hash was compared.
- `doctor`'s pre-flight file-completeness check now covers all 21 files `render.Project` generates, including `modules/services.nix` and `modules/filesystem-findings.nix` (both imported by the generated flake); previously 5 files were missing from the check, so a corrupted or missing module would only surface as an opaque Nix import error instead of a clear pre-flight failure.
- Plugin scanner timeouts now kill the plugin's whole process group, not just its top-level process; previously a plugin that forked a subprocess before exiting (e.g. a shell script) could leave that subprocess holding the output pipe open after being killed, so the scan blocked until the orphaned subprocess exited on its own instead of at the timeout.
- `serviceGenerationNotes`/`containerGenerationNotes` now explain a confirmed systemd service with no `ExecStart` and a confirmed container missing a name or image, respectively; previously both cases silently produced zero explanatory notes despite nothing being generated.
- `doctor` now exits non-zero when any check fails; previously it always printed the check result JSON and exited 0 regardless of `ok`, so a CI step running `doctor` could never actually fail.
- `baseline fetch` now pulls every catalog entry fully-qualified as `docker.io/library/<tag>@<digest>` instead of a bare tag; a bare `fedora:40` was found to resolve to a different image (`registry.fedoraproject.org/fedora`, a different digest) than Docker Hub's own `docker.io/library/fedora:40` under Podman's registry-alias resolution, a wrong-image risk that could affect any catalog entry depending on local container tooling/configuration, not just the newly-added Fedora ones.
- `isStatefulPath` no longer treats every file under `/home` as stateful data; previously any ordinary home-directory file that wasn't a script/executable/desktop-entry/service/secret (a plain document, a dotfile) got reported as a bogus `stateful-data`/`directory` entry with `Size: 0`, one per file, since `/home` had no corresponding collapse rule in `statefulTargets()` the way `/var/lib/postgresql` etc. do — and `/home` is scanned by default, not just under `--deep`.
- Cron `@special` schedules (`@reboot`, `@daily`, `@hourly`, etc.) are no longer silently dropped: `applyCronDetails` (system config scanning) and the backup/sync job scanner both assumed the classic 5-field time syntax and required at least 6 fields, so an `@reboot root /usr/local/bin/backup.sh`-style line left `Schedule`/`User`/`ExecStart` empty with no warning.
- DevOps config secret-risk warnings now come from actual file content (the `secret-refs` count every provider parser already computes) instead of a path-suffix guess (`.json`/`config`); the old heuristic missed `.config/helm/repositories.yaml` and `.terraformrc` entirely (both can carry real credentials) while incorrectly flagging any `*/config`-suffixed file regardless of its actual content.
- `redactSecretLikeText` (render and review packages) now also catches Basic-Auth-style credentials embedded in a URL (`scheme://user:pass@host`, e.g. in a cron/systemd command or a git remote) — previously it only redacted whitespace-separated `key=value` fields, so a credential embedded in a URL sailed through untouched into generated Nix/reports.
- **Security**: `quote()` (`internal/render`) now correctly escapes Nix string interpolation (`\$` for every `$`, not just Go's `%q` escaping) before embedding scanned values into generated `.nix` files. Previously, any scanned value containing `${...}` (plausible in a systemd/cron `ExecStart` line, which routinely contains shell variable syntax) became a live, evaluated Nix expression the next time the generated flake was built — a real code-injection path from scanned-host content into the user's actual system build, not just a report artifact.
- `dconf dump` output (desktop scanner) now redacts secret-like lines before storing them in the scan report; previously the entire GSettings database was embedded verbatim into `reports/desktop.md` with no content filtering at all, unlike every other content-based scanner in this codebase.
- Git remote URLs with embedded userinfo credentials (`https://oauth2:ghp_xxx@github.com/...`, a common private-repo access pattern) are now redacted at scan time before being stored in `report.GitSources`/rendered into reports — previously stored and rendered verbatim, unlike the DevOps/backup scanners, which already check line content for secret indicators before storing details.
- **Security**: the git scanner no longer follows a `.git/HEAD` ref containing `..` traversal segments outside the scan root. `HEAD`'s content is untrusted (read from the scanned filesystem), and a crafted `ref: ../../../../etc/shadow`-style value previously escaped `gitDir`/root via plain path collapsing — no symlink required at all. Guarded with a new `safeRealPath`/`safeStat`/`safeReadFile` (`internal/scanner/safepath.go`), a symlink- and traversal-bounded replacement for `os.Stat`/`os.ReadFile` on any path derived from scanned content, mirroring the bounded-path-check already used for tar extraction (`internal/baseline/fetch.go`'s `safeExtractPath`). More scanners are being migrated to these helpers in follow-up commits to close the same class of issue for symlink-following.
- **Security**: the DevOps config, secrets, backup/sync, and user-config scanners, plus the shared `readFile`/`exists` primitives (`internal/scanner/registry.go`), now resolve every scanned path through `safeStat`/`safeReadFile` before reading it. Previously a crafted symlink at a scanned path (e.g. in a mounted/extracted disk image scanned via `--root`) could transparently redirect a read to anywhere on the real host, with the result misattributed to the in-image path in the report — verified with regression tests that fail against the prior code and pass against the fix. Legitimate real-host symlinks (`/etc/os-release`, `/etc/resolv.conf`) keep working unaffected, since the check only rejects a path whose fully-resolved target escapes the scan root.
- **Security**: the hardware-config, system-config (systemd/cron), language ecosystem (npm/cargo/go/gem), and package ecosystem (flatpak/homebrew/AppImage) scanners are now also migrated to `safeStat`/`safeReadFile`, closing the same symlink-following gap in the remaining scanners.
- **Security**: the desktop, stateful-data, and apt scanners' remaining metadata-only (`Stat`-only) glob results are now also migrated to `safeStat`/`safeReadFile`, completing the symlink/traversal-bounding migration across every scanner in `internal/scanner`.

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
