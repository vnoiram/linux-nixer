# linux-nixer design and roadmap

This document records the design assumptions behind `linux-nixer` and the planned direction for future work.

## Product goal

`linux-nixer` helps migrate Debian/Ubuntu-like Linux environments to an editable NixOS + Home Manager configuration. It scans the current system, records findings in reviewable JSON, guides review decisions, and renders conservative Nix output plus reports for manual migration work.

The goal is not to blindly convert a mutable Linux host into Nix. The goal is to preserve enough context for a human to decide what should become declarative Nix, what should be reinstalled manually, and what must stay outside Git and generated configuration.

## Design principles

- Conservative generation: only high-confidence, reviewed findings become generated Nix.
- Confirmed-only rendering: `confirmed` findings are eligible for Nix output; `candidate`, `todo`, and `migration-note` remain in reports and comments.
- Secret safety: credentials, keys, token-bearing config, browser profiles, and credential stores are never embedded into generated Nix.
- Stateful data safety: databases, queues, VM images, container volumes, uploads, and application state are reported as migration notes with backup/restore checklist items.
- Review-first workflow: scan output is intentionally noisy but structured; review, summary, validate, and checklist steps narrow it before generation.
- Baseline and diff support: scans can run against mounted rootfs fixtures and compare against distro baselines to identify non-base files, including files whose permissions changed with unchanged content, not just content or brand-new files.
- `baseline fetch` builds a real baseline manifest for a distro release by pulling its official Docker/Podman image and hashing its actual filesystem, so common Ubuntu/Debian releases don't require a local rootfs and never rely on hand-curated file data.
- Standard-library core: the CLI, scanners, review flow, validation, and rendering are implemented in Go with minimal moving parts.

## Nix mapping maintenance

`internal/mapping/mapping.go` is the lookup table from scanned package manager names (apt, npm, pipx, cargo, go-install, gem) to Nix package attribute paths, consumed by `Candidates(manager, name)`. It is conservative by construction: an unmapped name stays unmapped rather than getting a guessed attribute path, and structural tests in `mapping_test.go` (`TestMappingKeysAreNormalized`, `TestMappingValuesAreNonEmpty`, `TestMappingAliasesResolveToRealEntries`, `TestMappingAliasManagersExist`) guard the whole table's integrity, not just a handful of example lookups.

Review checklist for adding a mapping entry:

1. Only add an entry for a manager a scanner actually calls (see the call sites listed in `mapping.go`'s package doc comment) — no speculative tables for managers nothing scans yet.
2. Verify the target is a real, current nixpkgs attribute path before adding it (e.g. via `nix search nixpkgs <name>` or search.nixos.org). Never guess — if it can't be verified, leave the name unmapped rather than add a plausible-looking but wrong mapping; a wrong confirmed mapping is worse than none, per the conservative-generation principle.
3. Add the entry to the correct manager's table with a lowercase, trimmed key (or add a `mappingAliases` entry when the scanned name differs from the canonical key).
4. Add at least one case to `mapping_test.go` exercising the new entry, then run `go test ./internal/mapping/...` — the structural tests run automatically and need no per-entry maintenance.

## Current architecture

- CLI commands:
  - `scan` collects host findings into scan JSON.
  - `capture` runs scan, review, summary, and Nix generation as one workflow.
  - `review` applies repeatable policy rules or interactive decisions.
  - `summary` reports pending work, review focus, and generated Nix impact.
  - `validate` checks schema, decisions, and protected finding rules.
  - `generate` renders the NixOS/Home Manager project.
  - `doctor` validates generated project files and can run Nix VM checks.
  - `baseline create` records rootfs baseline manifests.
  - `policy init` creates repeatable review policy templates.
- Scanner registry:
  - Dedicated scanners collect packages, language tooling, Git sources, containers, services, system config, DevOps config, user config, desktop config, hardware/peripherals, backups, secrets, stateful data, and filesystem diff findings.
  - Scanners prefer safe summaries and markers over raw file contents.
  - A representative-host integration test runs the full registry together against a synthetic multi-domain tree, guarding scanner ordering and dedup (e.g. secrets vs. filesystem diff) beyond what per-scanner unit tests can catch.
- Data model:
  - `ScanReport` is the shared JSON boundary.
  - `Package`, `Item`, `Service`, `Container`, `FileFinding`, and related structs carry review decisions and safe details.
- Review and policy:
  - Non-interactive rules can confirm, exclude, mark TODO, or mark migration notes.
  - `policy init --preset <name>` seeds a policy tuned for a common migration style (`workstation`, `server`, `developer-machine`, `minimal-audit`) instead of the generic template, by pre-setting `confirmKinds`/`excludeKinds` for that archetype.
  - `review --export-decisions`/`--import-decisions` (also on `capture`) make individual, per-finding decisions repeatable and shareable — keyed by finding identity (manager+name, path, or kind+path) rather than scan position, so decisions carry across a re-scan or a teammate's scan of a similar host and win over policy category rules for the same finding.
  - `summary --compare-decisions` diffs the current scan against a previously exported decisions snapshot for migration progress tracking across repeated scans of the same host: newly decided, changed, regressed to pending, and no-longer-present findings.
  - Interactive review shows safe context notes, details, Nix mapping impact, and protected-finding reasons, with per-section progress counts, a skip-rest-of-section command, and an optional pending-only filter that hides findings already resolved by policy or safety rules.
  - Container, systemd service, and cron job notes reflect the exact render-time generation gates (missing name/image, secret-like exec, environment files, unmapped ports/mounts, missing cron schedule/user), not a blanket "generates when safe" claim, so the safe/unsafe outcome is visible before the decision is made.
- Rendering:
  - Generated projects include flake, host config, Home Manager config, service/container/filesystem modules, reports, and migration checklist.
  - Rendering is conservative and mostly emits confirmed packages, safe user options, safe shell/home options, container runtime enables, limited systemd service/timer options, and confirmed cron jobs with a schedule/user/command as `services.cron.systemCronJobs` entries.
- Validation and doctor:
  - Validation rejects unsupported schema versions, unknown decisions, and unsafe confirmed protected findings.
  - Doctor checks generated project structure and optionally validates/builds Nix VM artifacts. Its file-completeness check covers every file `render.Project` produces (including the modules the generated flake imports), kept in sync by a test that walks a real render output and fails if either side drifts.
- Release:
  - CI runs Go checks.
  - Tag-based release builds Linux amd64/arm64 archives, injects version/commit/build-date metadata, smoke-tests artifacts, produces checksums, and creates a GitHub Release.
  - `scripts/release-check.sh` (`make release-check`) runs the full release validation locally: changelog heading check, format/vet/test, cross-arch build, checksums, and archive smoke test. The release workflow calls the same script, so a passing local run mirrors CI.
  - `scripts/check-changelog.sh` (`make changelog-check`) gates releases on `CHANGELOG.md` having a matching `## [version]` heading.

## Detection scope

Current scanner domains include:

- apt/dpkg packages, install reasons, repositories, keyrings, preferences, and apt client config
- Linux users, login shells, home directories, system users, supplementary groups, and privileged group membership
- snap, flatpak, AppImage, and Homebrew with safe origin/scope/channel/location markers
- npm/pnpm/yarn globals, Python/pipx/venv/project files, Conda, Cargo, Go-installed binaries, Ruby gems, and version managers
- Git checkouts with remotes, commits, dirty state, submodules, and build hints
- Docker/Podman containers, images, ports, mounts, env keys, and compose files
- systemd services/timers, cron jobs, network/firewall/SSH/VPN summaries, sudo/PAM/polkit/AppArmor/fail2ban/auditd markers, web servers, and kernel/device tuning
- DevOps config for Kubernetes, Docker client, Helm, Terraform, AWS, GCP, Azure, and CI/CD automation
- shell/user config, SSH client/key markers, GPG/key stores, tmux/starship/plugin trees, and `.local/bin` executables
- desktop config, fonts, themes/icons, autostart, dconf, KDE/i3/sway/input method config, browser profiles/extensions, and editor profiles
- hardware/peripheral config for CUPS, Bluetooth/BlueZ, SANE, PipeWire/PulseAudio/ALSA, fprint/U2F/YubiKey/smartcard, fwupd/TLP/UPower, and input remappers
- stateful data markers for databases, queues, search, monitoring, container runtimes, VM images, `/srv`, and uploads
- backup/sync config and job markers for restic, borg, kopia, rclone, rsync, syncthing, Timeshift, and Duplicati
- filesystem findings such as ELF executables, shebang scripts, desktop entries, systemd units, configs, secrets, stateful data, and location hints

## Output strategy

- Generated Nix:
  - Confirmed packages with known Nix candidates become system or Home Manager packages.
  - Confirmed human users become `users.users` entries with safe shells and allowlisted groups.
  - Confirmed shell/home config markers enable selected Home Manager programs.
  - Confirmed container runtimes enable Docker/Podman flags, and confirmed containers with a known name and image render individual `virtualisation.oci-containers.containers` entries with safe ports and volumes; unmapped ports, unsafe mounts, and environment values stay as migration notes.
  - Confirmed safe systemd services/timers can render limited service/timer options.
  - Confirmed cron jobs with a schedule, user, and non-secret-like command render as `services.cron.systemCronJobs` entries.
- Reports:
  - Domain reports preserve context that should not be converted automatically.
  - Reports include safe details, counts, markers, and redacted summaries.
- Migration checklist:
  - Manual work is grouped by package, source, language, service, container, DevOps, filesystem, secret, stateful, backup, user/desktop, and hardware domains.
- Summary:
  - Review summary tracks pending findings, unmapped package gaps, manual migration notes, protected findings, and generated Nix impact.

## Safety boundaries

These are intentionally not embedded into generated Nix:

- raw secrets, private keys, tokens, password-bearing files, credentials, and credential stores
- browser cookies, histories, sessions, saved credentials, and raw profiles
- cloud credentials and DevOps auth material
- database/queue/search/monitoring/container/VM/application state
- repository trust keys and package signing material
- raw service unit bodies, raw dotfile bodies, and raw config bodies
- environment file contents and secret-like service command arguments

When in doubt, scanners should emit `candidate`, `todo`, or `migration-note` with safe details instead of generating Nix.

## Roadmap

### Near term

- Continue safe generated Nix expansion for confirmed findings, especially container services and Home Manager options.
- Improve interactive review with filtering, section skipping, and better progress indicators.
- Harden release workflow with changelog checks, local release validation commands, and clearer artifact metadata.
- Expand fixture coverage for representative Debian/Ubuntu hosts and arbitrary non-base filesystem changes.
- Improve scanner explanations so reports make the review decision easier without exposing raw config.

### Mid term

- Improve baseline diff precision and add curated baseline catalog support for common Ubuntu/Debian releases.
- Move Nix mapping maintenance toward a documented, testable table with review policy for additions.
- Add more service/container/config conversion candidates while keeping raw content out of generated Nix.
- Add policy presets for common migration styles such as workstation, server, developer machine, and minimal audit.
- Improve import/export flows for repeatable migration sessions and team review.

### Long term

- Define a stable plugin or scanner extension API.
- Support richer per-distro baseline catalogs and offline fixture packs.
- Generate more structured Nix modules with explicit migration annotations.
- Strengthen VM/dry-run validation so generated configs can be tested before touching a real host.
- Add migration progress tracking across repeated scans of the same machine.

## Non-goals for now

- Fully automatic, unattended Linux-to-NixOS conversion.
- Storing or transforming raw secrets.
- Embedding stateful data into Git or generated Nix.
- Perfect parsing of every config format.
- Replacing human review for ambiguous package, service, or credential decisions.
