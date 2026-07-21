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
- `baseline import` builds the same kind of manifest from an already-downloaded flat rootfs tar (an official distro base-rootfs tarball, or a carried-over `docker export` tar) — for offline use with neither a container backend nor network access, with automatic gzip decompression and `--tar -` stdin support.
- Standard-library core: the CLI, scanners, review flow, validation, and rendering are implemented in Go with minimal moving parts.

## Nix mapping maintenance

`internal/mapping/mapping.go` is the lookup table from scanned package manager names (apt, npm, pipx, cargo, go-install, gem) to Nix package attribute paths, consumed by `Candidates(manager, name)`. It is conservative by construction: an unmapped name stays unmapped rather than getting a guessed attribute path, and structural tests in `mapping_test.go` (`TestMappingKeysAreNormalized`, `TestMappingValuesAreNonEmpty`, `TestMappingAliasesResolveToRealEntries`, `TestMappingAliasManagersExist`) guard the whole table's integrity, not just a handful of example lookups.

Review checklist for adding a mapping entry:

1. Only add an entry for a manager a scanner actually calls (see the call sites listed in `mapping.go`'s package doc comment) — no speculative tables for managers nothing scans yet.
2. Verify the target is a real, current nixpkgs attribute path before adding it (e.g. via `nix search nixpkgs <name>` or search.nixos.org). Never guess — if it can't be verified, leave the name unmapped rather than add a plausible-looking but wrong mapping; a wrong confirmed mapping is worse than none, per the conservative-generation principle.
3. Add the entry to the correct manager's table with a lowercase, trimmed key (or add a `mappingAliases` entry when the scanned name differs from the canonical key).
4. Add at least one case to `mapping_test.go` exercising the new entry, then run `go test ./internal/mapping/...` — the structural tests run automatically and need no per-entry maintenance.

## Baseline catalog maintenance

`internal/baseline/catalog.go` is the curated lookup table from distro/release pairs to verified Docker Hub image references, consumed by `CatalogImage(distro, release)` and listed via `baseline list`/`CatalogEntries()`. Same conservative-by-construction shape as the Nix mapping table above: an unlisted distro/release stays unlisted rather than being passed through to `docker pull` as a guessed `distro:release` tag, and structural tests in `catalog_test.go` (`TestCatalogKeysAreNormalized`, `TestCatalogEntriesSorted`) guard the whole table, not just a handful of example lookups. `baseline fetch` rejects any distro/release not in the catalog before attempting a pull, so an unsupported combination fails with a clear message pointing at `baseline list` instead of an opaque `docker pull` error.

Review checklist for adding a catalog entry:

1. Verify the image reference is a real, current official image on Docker Hub before adding it (e.g. `docker pull <image>` succeeds, or check hub.docker.com) — never guess a `distro:release` tag; if it can't be verified, leave the combination out of the catalog rather than add one that might 404 or resolve to something unexpected.
2. Add the entry under the correct distro's table with a lowercase, trimmed distro key and a trimmed release key (`CatalogImage` normalizes the distro but not the release, matching how `--release` is typically an exact version string like `24.04`, not free text).
3. Add at least one case to `catalog_test.go` exercising the new entry, then run `go test ./internal/baseline/...` — the structural tests run automatically and need no per-entry maintenance.

## Current architecture

- CLI commands:
  - `scan` collects host findings into scan JSON.
  - `capture` runs scan, review, summary, and Nix generation as one workflow.
  - `review` applies repeatable policy rules or interactive decisions.
  - `summary` reports pending work, review focus, and generated Nix impact.
  - `validate` checks schema, decisions, and protected finding rules.
  - `generate` renders the NixOS/Home Manager project.
  - `doctor` validates generated project files and can run Nix VM checks.
  - `baseline create`/`fetch`/`import` record rootfs baseline manifests (from a local rootfs, a pulled distro image, or an already-downloaded tar, respectively); `baseline list` shows the curated catalog `fetch` will accept.
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
  - `validate --decisions decisions.json --policy policy.json` checks a decisions file for consistency with a policy's kind vocabulary (`confirmKinds`/`excludeKinds`/`todoKinds`/`migrationNoteKinds`) and warns about stale entries (the recorded decision disagrees with what the current policy would now produce for that kind — a sign the policy changed since the decision was made) or unresolvable ones (unrecognized domain, or a key that doesn't carry a recoverable kind). Only `container`/`service`/`git-source`/`item` entries have a kind checkable this way; `package` (gated by `confirmManagers`, not kinds), `filesystem-finding` (kind is a per-finding field not stored in the decisions file), and `stateful-data` (never kind-gated) are intentionally left unchecked. Always warnings, never errors — a stale or unresolvable entry still works correctly when reapplied, since an explicit decision always wins over policy category rules for the same finding.
  - Interactive review shows safe context notes, details, Nix mapping impact, and protected-finding reasons, with per-section progress counts, a skip-rest-of-section command, and an optional pending-only filter that hides findings already resolved by policy or safety rules.
  - Container, systemd service, and cron job notes reflect the exact render-time generation gates (missing name/image, secret-like exec, environment files, unmapped ports/mounts, missing cron schedule/user), not a blanket "generates when safe" claim, so the safe/unsafe outcome is visible before the decision is made.
- Rendering:
  - Generated projects include flake, host config, Home Manager config, service/container/filesystem modules, reports, and migration checklist.
  - Rendering is conservative and mostly emits confirmed packages, safe user options, safe shell/home options, container runtime enables, limited systemd service/timer options, and confirmed cron jobs with a schedule/user/command as `services.cron.systemCronJobs` entries.
- Validation and doctor:
  - Validation rejects unsupported schema versions, unknown decisions, and unsafe confirmed protected findings.
  - Doctor checks generated project structure and optionally validates/builds Nix VM artifacts. Its file-completeness check covers every file `render.Project` produces (including the modules the generated flake imports), kept in sync by a test that walks a real render output and fails if either side drifts.
  - `doctor --boot` scans the VM boot script's captured console output for known failure signatures (kernel panic, emergency mode, unable to mount root fs, etc.) regardless of whether the process timed out, exited with an error, or exited cleanly — a hung or crashed VM no longer passes silently just because the timeout fired before it crashed outright. This is a heuristic improvement over blind timeout-as-success, not a positive proof of a successful boot (no `nix`/QEMU is available to develop or test against a real VM boot in this environment); that verification gap is intentionally left to a dedicated CI job with a real Nix installation (see roadmap).
- Release:
  - CI runs Go checks.
  - A separate `nix-verify` CI job installs a real Nix toolchain (`DeterminateSystems/determinate-nix-action`), runs `capture` against the CI runner itself to produce a real generated flake, and runs `doctor --vm` against it — a real `nix flake check` and a real VM derivation build, closing the "designed but never executed against real `nix`" gap for the generated flake/modules. `--boot` is intentionally left out: standard GitHub-hosted runners have no `/dev/kvm` (no nested virtualization), and the generated VM script needs it — booting stays untested in CI, an honest, documented gap rather than a silent one. This was revisited (per the roadmap's "investigate larger runners" item) rather than left as an open question: every GitHub-hosted Linux runner tier, standard or larger, runs as a nested VM itself with no exposed `/dev/kvm` — nested virtualization needs a self-hosted runner on real hardware (or a nested-virt-capable host), which this project has no infrastructure for. This gap is expected to persist rather than resolve as GitHub adds larger hosted-runner tiers, since the constraint is architectural (nested-VM hosts), not a resource limit a bigger runner tier would lift.
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

## Plugin scanners

`scan`/`capture --plugin PATH` (repeatable) run an external executable as an extra scanner, without any Go plugin loading or module-distribution requirement — a plugin is any executable, in any language, that speaks a small JSON protocol.

- **Invocation**: `<path> scan`, with a JSON `PluginRequest` written to its stdin:
  ```json
  {
    "schemaVersion": "linux-nixer.plugin-request.v1",
    "root": "/",
    "deep": false,
    "sudo": false,
    "includes": [],
    "excludes": []
  }
  ```
  `root`/`deep`/`includes`/`excludes` mirror the main scan's own options. `sudo` is **informational only** — it reflects whether the main scan was run with `--sudo`, but the plugin process itself is always invoked as the current user, never elevated, regardless of this flag.
- **Output**: the plugin must write a JSON `model.ScanReport` (the same schema as `scan.json`/`reviewed.json`, `schemaVersion: "linux-nixer.scan.v1"`) to stdout. Its `packages`, `services`, `containers`, `items`, and `warnings` are read and merged into the real scan report — every other field (`host`, `users`, `languages`, `gitSources`, `desktop`, `filesystemDiff`, `statefulData`) is ignored. `Item` (`kind`, `name`, `path`, `source`, `reason`, `details`) is this schema's general-purpose finding type, already used by most built-in scanners, and flows through review/decisions/summary/checklist exactly like a built-in finding once merged — a plugin doesn't need to know anything about this tool's per-domain Nix-mapping conventions to contribute something useful. A plugin that does know those conventions can instead (or additionally) contribute directly to `packages`/`services`/`containers`, which flow through the exact same review (`decidePackage`/`decideFinding`) and generation logic as built-in scanner output — including rendering into the generated Nix config once confirmed.
- **Timeout**: 30 seconds by default, overridable per invocation with `--plugin-timeout DURATION` on `scan`/`capture` (applies to every plugin in that run); a plugin that doesn't produce output in time is treated as a scan error for that one scanner (surfaced as a `warnings` entry, same as any other scanner failure — never aborts the whole scan) rather than hanging the run. The timeout kills the plugin's whole process group, not just its top-level process, so a plugin that forks its own subprocesses (e.g. a shell script) can't outlive the timeout by leaving an orphaned child holding its output pipe open.
- **Trust model**: a plugin is an arbitrary executable the user explicitly named via `--plugin PATH` (or a policy file's `plugins` list, see below) — the same trust level as any other file/path input this CLI already takes (`--policy`, `--baseline`), not a new attack surface. Review already respects a pre-set `decision` other than `""`/`candidate` as-is, for any finding regardless of its scanner (this predates plugins and applies equally to a built-in scanner's output) — a plugin that sets `"decision": "confirmed"` on a `package`/`service`/`container` it emits will flow straight into the rendered Nix config, not just a checklist entry the way an `item` does. Not a new trust rule, but worth knowing given the larger blast radius of these three fields versus `items`.
- **Policy-configured plugins**: a policy file's `plugins` list sets default plugin paths, merged with `--plugin` the same way `includePaths`/`excludePaths` merge with `--include`/`--exclude` — policy-provided paths first, then CLI-provided paths, deduplicated.
- **Protocol validation**: `plugin check --plugin PATH` invokes a single plugin once with a synthetic request (root `/`, nothing else set) and validates its output with the exact same structural checks `validate` runs on a real `scan.json`/`reviewed.json` — including the `items[].kind`/`items[].path`-or-`.name`/`items[].decision` checks that apply directly to what a plugin is allowed to contribute. Lets a plugin author (or this tool's user) catch a broken plugin before pointing a real `scan`/`capture` at it, with the same `--json` machine-readable option as `validate`.
- **Compatibility policy**: the protocol has two version constants a plugin author depends on — `PluginRequestSchemaVersion` (`"linux-nixer.plugin-request.v1"`, `internal/scanner/plugin.go`) for what's written to a plugin's stdin, and `model.SchemaVersion` (`"linux-nixer.scan.v1"`, `internal/model/model.go`, shared with `scan.json`/`reviewed.json`) for what a plugin must write to stdout. **Additive** (safe within the same version, no plugin action needed): a new optional `PluginRequest` field a plugin may ignore; merging an additional, previously-ignored top-level `ScanReport` field into the real scan — this already happened once, when `packages`/`services`/`containers` merging was added on top of the original `items`/`warnings`-only contract without a version bump, since an existing plugin that only emitted `items`/`warnings` kept working unchanged. **Breaking** (requires a new `schemaVersion`): renaming, removing, or retyping an existing field, or changing what a field means or which fields are required for a successful merge. The actual enforcement point is lenient by design: `runPluginProcess` rejects a plugin's output only if its `schemaVersion` is *non-empty and* doesn't match `model.SchemaVersion` — an empty `schemaVersion` is tolerated, so a plugin that never bothers tracking version bumps keeps working as long as it doesn't claim a wrong one.

Minimal example plugin (shell):
```sh
#!/bin/sh
cat >/dev/null  # request JSON is ignored by this trivial example
cat <<'JSON'
{"schemaVersion":"linux-nixer.scan.v1","items":[{"kind":"custom-finding","path":"/opt/example","reason":"found by my-plugin"}]}
JSON
```

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
  - `reports/migration-annotations.nix` is a structured, standalone Nix attribute set tracing every container/systemd service/cron job/package (both `environment.systemPackages` and Home Manager `home.packages`) — confirmed or not — to the Nix option it renders as, or a note explaining why not. A confirmed finding's note explains a structural/safety reason (missing name/image, secret-like exec, no Nix mapping, etc.); a non-confirmed finding's note explains the decision itself instead (`excluded`, `todo`, `migration-note`, or still a pending `candidate`) via `decisionNote` in `internal/render/render.go`, since it was never eligible to render regardless of any structural check. Deliberately not added to any `imports` list, so it can carry arbitrary structured data without risking `nix flake check` rejecting an undeclared option. Its `users` section covers every scanned user rather than only confirmed ones, since `model.User` has no review decision to filter on — inclusion instead mirrors the same structural gate (not a system user, not `root`, home under `/home/`) that decides whether a user is actually rendered.
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
- Let policy files specify default `--plugin` paths, consistent with every other scan option (`root`, `sudo`, `deep`, `baseline`, `includes`, `excludes`) already being policy-configurable.
- Add a `--plugin-timeout` flag to override `PluginScanner`'s default 30s timeout per invocation.
- Add a plugin protocol validation command that invokes a single plugin with a synthetic request and checks its JSON output against the schema, to catch a broken plugin before a real scan.
- Add a small curated baseline catalog (distro/release → verified image reference, in the same conservative-table spirit as `internal/mapping/mapping.go`) plus a `baseline list` command/flag, and have `baseline fetch` validate `--distro`/`--release` against it before attempting a pull instead of failing opaquely inside `docker pull` (currently `internal/baseline/fetch.go` builds the image reference as a bare `distro:release` concatenation with no validation).
- Document a compatibility policy for the plugin JSON protocol (what counts as an additive change a plugin may safely ignore vs. a breaking change requiring a new `schemaVersion`) and add a regression test guarding the existing `linux-nixer.plugin-request.v1`/`linux-nixer.scan.v1` constants — the protocol has already grown once compatibly (adding `packages`/`services`/`containers` merging) without this being written down anywhere.

### Mid term

- Improve baseline diff precision and add curated baseline catalog support for common Ubuntu/Debian releases.
- Move Nix mapping maintenance toward a documented, testable table with review policy for additions.
- Add more service/container/config conversion candidates while keeping raw content out of generated Nix.
- Add policy presets for common migration styles such as workstation, server, developer machine, and minimal audit.
- Improve import/export flows for repeatable migration sessions and team review.
- Extend the plugin protocol to merge `Packages`/`Services`/`Containers` in addition to `Items`/`Warnings`, so plugins can contribute richer, per-domain findings.
- Extend `reports/migration-annotations.nix` to cover packages and users, not just containers/systemd services/cron jobs.
- Add a consistency check between `decisions.json` and the current policy's kind vocabulary, warning about stale or unresolvable decision entries.
- Extend `reports/migration-annotations.nix` to also explain excluded/todo/migration-note findings, not just confirmed ones, so the one structured trace file answers "why isn't this in Nix" for everything, not only "why is this in Nix."
- Bundle small pre-built baseline manifests for a handful of common releases (e.g. ubuntu 22.04/24.04, debian 11/12) as release artifacts or a `baselines/catalog/` directory, built on top of the near-term baseline catalog and `baseline import`'s existing tar-based path, so the fully offline case doesn't require separately obtaining a rootfs tar.
- Investigate `/dev/kvm` availability on larger GitHub-hosted runners (or a self-hosted runner) to finally exercise `doctor --boot` in the `nix-verify` CI job; if no viable free option exists, document that conclusion explicitly instead of leaving the gap silently unrevisited.

### Long term

- Define a stable plugin or scanner extension API.
- Support richer per-distro baseline catalogs and offline fixture packs.
- Generate more structured Nix modules with explicit migration annotations.
- Strengthen VM/dry-run validation so generated configs can be tested before touching a real host.
- Add migration progress tracking across repeated scans of the same machine.
- Strengthen `doctor --boot`'s VM-boot detection beyond the current timeout-as-success heuristic.
- Add a CI job with a real Nix installation to verify `nix`-touching functionality (`doctor --vm`/`--boot`, `scripts/release-check.sh`, the generated flake/modules) that has so far only ever been designed, never executed against real `nix`.
- Consider incremental/streaming plugin output for scans too large to buffer and print within the (overridable) timeout window, now that the protocol carries richer per-domain data than the original items/warnings-only design.
- Consider signed/verified baseline manifests once a curated baseline catalog exists, so a fetched or imported baseline can't be silently tampered with between fetch and later diff use.

## Non-goals for now

- Fully automatic, unattended Linux-to-NixOS conversion.
- Storing or transforming raw secrets.
- Embedding stateful data into Git or generated Nix.
- Perfect parsing of every config format.
- Replacing human review for ambiguous package, service, or credential decisions.
