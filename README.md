# linux-nixer

`linux-nixer` scans Debian/Ubuntu-like Linux environments and generates an editable NixOS + Home Manager flake.

The project is intentionally conservative: it detects a wide range of system state, but only turns high-confidence items into Nix automatically. Risky items such as secrets, keys, large stateful data, browser profiles, and cloud credentials are reported as migration notes instead of being embedded into generated Nix files.

Generated Nix settings only include findings marked `confirmed`. Findings left as `candidate` stay in reports and TODO comments until reviewed.

See [DESIGN_AND_ROADMAP.md](DESIGN_AND_ROADMAP.md) for design assumptions, safety boundaries, and planned work.

## Current status

This is an early implementation scaffold. It includes:

- Go CLI commands: `scan`, `capture`, `review`, `summary`, `validate`, `generate`, `doctor`, `baseline create`, `policy init`
- Registry-based scanners for host/user metadata, groups, apt, language tooling, Git sources, containers, secrets, system config files, DevOps/project config, user shell settings, desktop settings, hardware/peripheral settings, and filesystem findings
- Dedicated package ecosystem scanners and safe detail summaries for snap, flatpak, AppImage, and Homebrew on Linux
- Baseline manifest creation for rootfs comparisons
- Nix flake project rendering
- Richer generated modules and reports for package sources, alternative package ecosystems, services, containers, language ecosystems, filesystem findings, system config, DevOps config, user shell settings, desktop settings, hardware/peripheral settings, and development projects
- Service detail reporting for systemd units, timers, and cron schedules
- Confirmed-only rendering for system packages, Home Manager packages, and container runtime enables
- Conservative Nix option rendering for detected users, safe shell enables, and selected confirmed Home Manager program enables
- Expanded conservative Nix package mapping for apt, npm, pipx/Python CLI, cargo, go-install, and gem findings, including common CLI aliases
- Non-interactive review rules for confirming, excluding, or deferring findings
- Interactive review mode using only the Go standard library
- Review summary output and pending-finding gates before generating Nix
- Scan JSON validation for schema, decisions, and protected findings
- One-shot capture workflow for scan, auto-safe review, summary, and Nix generation
- Reusable JSON policy files for repeatable scan and review rules
- `doctor --vm` support for building the generated NixOS VM derivation
- Optional `doctor --boot` check for starting the generated VM script with a timeout
- Baseline IDs such as `ubuntu:24.04` resolved from local `baselines/` or user cache
- Read-only `scan --sudo` fallback for selected host files
- Unit and fixture-style tests, including seeded arbitrary-directory executable detection
- GitHub Actions CI and tag-based release workflow

## Usage

```sh
go build -o bin/linux-nixer ./cmd/linux-nixer

bin/linux-nixer scan --out scan.json
bin/linux-nixer scan --sudo --out scan.json
bin/linux-nixer capture --out linux-nixer-output --sudo --deep
bin/linux-nixer policy init --out linux-nixer-policy.json
bin/linux-nixer capture --policy linux-nixer-policy.json --out linux-nixer-output
bin/linux-nixer review --scan scan.json --out reviewed.json --auto-safe
bin/linux-nixer validate --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
bin/linux-nixer generate --scan reviewed.json --out nix-config
bin/linux-nixer doctor --project nix-config
bin/linux-nixer help capture
```

For fixture or mounted rootfs scans:

```sh
bin/linux-nixer scan --root /path/to/rootfs --include /random-seed-42 --out scan.json
bin/linux-nixer capture --root /path/to/rootfs --include /random-seed-42 --out linux-nixer-output
```

`capture` writes `scan.json`, `reviewed.json`, `summary.md`, and `nix-config/` under the output directory. It applies the same conservative auto-safe review as `review --auto-safe`; use the split `scan` and `review --interactive` flow when you want to approve findings manually before generating Nix.
After capture, review `nix-config/reports/migration-checklist.md` for manual package, secret, stateful data, and configuration migration steps.

Policy files make scan and review decisions repeatable:

```sh
bin/linux-nixer policy init --out linux-nixer-policy.json
bin/linux-nixer scan --policy linux-nixer-policy.json --out scan.json
bin/linux-nixer review --policy linux-nixer-policy.json --scan scan.json --out reviewed.json
bin/linux-nixer capture --policy linux-nixer-policy.json --out linux-nixer-output
```

`policy init --preset <name>` starts from a template tuned for a common migration style instead of the generic one: `workstation`, `server`, `developer-machine`, or `minimal-audit` (confirms nothing automatically — the most conservative starting point). Run `bin/linux-nixer help policy init` for what each preset confirms.

Policy paths are plain prefixes, not globs. CLI list flags are merged with policy lists; explicitly provided boolean and string flags override policy values.

`--export-decisions`/`--import-decisions` (on `review` and `capture`) make specific per-finding decisions repeatable, not just category-level policy rules. A decisions file records every non-default decision keyed by finding identity (e.g. `apt:curl`, `systemd:app.service`), so it stays meaningful across a re-scan of the same host or a teammate's scan of a similar one — commit it alongside your policy file for team review:

```sh
bin/linux-nixer review --scan scan.json --out reviewed.json --confirm-kind service --export-decisions decisions.json
bin/linux-nixer review --scan scan-later.json --out reviewed-later.json --import-decisions decisions.json
```

Imported decisions win over policy `confirmKinds`/`excludeKinds` for the same finding — an explicit prior decision outranks a category default.

Create a baseline manifest. If Docker or Podman is available, `baseline fetch` builds one from the distro's official image — no local rootfs needed:

```sh
bin/linux-nixer baseline fetch --distro ubuntu --release 24.04
bin/linux-nixer scan --root /path/to/current-root --baseline ubuntu:24.04 --out scan.json
```

Without Docker/Podman, or for a custom/offline rootfs, use `baseline create` against a mounted or extracted filesystem instead:

```sh
mkdir -p baselines
bin/linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baselines/ubuntu-24.04.json
```

`--baseline` accepts either a JSON path or an ID such as `ubuntu:24.04`. IDs resolve to `baselines/ubuntu-24.04.json` in the current project first, then to the user cache under `linux-nixer/baselines/`. `baseline fetch` writes to that same default path when `--out` is omitted, so a fetched baseline is immediately usable by ID.

Review decisions can be adjusted without editing JSON by hand:

```sh
bin/linux-nixer review \
  --scan scan.json \
  --out reviewed.json \
  --auto-safe \
  --interactive \
  --confirm-manager apt \
  --confirm-kind service \
  --exclude-path /home/alice/Downloads
```

Interactive review shows safe context notes such as Nix mapping impact, limited details, unmapped-package markers, and protected-finding reasons. It accepts `c` confirmed, `k` candidate, `t` todo, `m` migration-note, `x` excluded, `s` skip, and `q` quit. Secret-like and stateful findings cannot be confirmed interactively; they remain migration notes unless excluded.

Summarize reviewed decisions before generating Nix:

```sh
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
```

The summary includes review focus and next actions for unmapped packages, manual migration notes, protected findings, and generated Nix impact. `--fail-on-pending` exits non-zero when `candidate` or `todo` findings remain. `migration-note` findings are treated as expected manual migration work and do not fail the gate.

Validate scan or reviewed JSON before generating Nix:

```sh
bin/linux-nixer validate --scan reviewed.json
bin/linux-nixer validate --scan reviewed.json --json
bin/linux-nixer validate --scan reviewed.json --strict
```

`--strict` rejects unknown JSON fields in addition to checking schema version, known decision values, required identifiers, and protected secret/stateful findings.

VM validation builds the generated NixOS VM derivation when Nix is available:

```sh
bin/linux-nixer doctor --project nix-config --vm --host generated
bin/linux-nixer doctor --project nix-config --vm --boot --timeout 20s --host generated
```

Generated projects include:

- `flake.nix`
- `hosts/generated/configuration.nix`
- `users/home.nix`
- `modules/containers.nix`
- `modules/services.nix`
- `modules/filesystem-findings.nix`
- `reports/package-sources.md`
- `reports/filesystem.md`
- `reports/users.md`
- `reports/containers.md`
- `reports/git-sources.md`
- `reports/languages.md`
- `reports/migration-report.md`
- `reports/migration-checklist.md`
- `reports/system-config.md`
- `reports/devops-config.md`
- `reports/backup-sync.md`
- `reports/dev-projects.md`
- `reports/user-config.md`
- `reports/desktop.md`
- `reports/hardware.md`

## Scanner domains

- apt/dpkg packages, manual install hints, apt repositories, keyrings, preferences, and apt config
- Linux users, login shells, home directories, system-user hints, supplementary groups, and privileged group membership
- snap, flatpak, AppImage, and Homebrew on Linux, including safe origin/scope/channel/location markers
- npm/pnpm/yarn global packages and local node package manager metadata
- Python venv, pipx, pyproject, requirements, Poetry, Pipenv, uv, and Conda environment markers
- version managers such as asdf, mise, nvm, fnm, volta, pyenv, rbenv, sdkman, and conda
- cargo, gem, `go install` style user binaries, and Rust/Go/Ruby project manifests
- Git checkouts under common source locations with remote, commit, branch, dirty, submodule, and build hints
- Docker/Podman containers, inspect metadata, and compose files
- stateful data markers for databases, queues, search, monitoring, container runtimes, VM images, and `/srv` application data
- backup/sync config and job markers for restic, borg, kopia, rclone, rsync, syncthing, Timeshift, and Duplicati
- systemd, cron, network/firewall/SSH/VPN safe summaries, sudo/PAM/polkit/AppArmor/fail2ban/auditd markers, web server, CI/CD automation, and kernel/device tuning markers
- DevOps config markers such as Kubernetes, Docker client config, Helm, Terraform, AWS, GCP, and Azure
- shell/user settings such as bash, zsh, fish, profile/env files, direnv, git, ssh keys/known hosts, gpg/key stores, tmux, starship, shell plugin trees, and `.local/bin` executables
- desktop environment markers, fonts, themes/icons, autostart entries, GNOME dconf dumps, KDE/i3/sway/input method config, browser profiles/extensions, and common terminal/editor settings
- hardware/peripheral markers such as CUPS printers, Bluetooth/BlueZ, SANE scanners, PipeWire/PulseAudio/ALSA, fprint/U2F/YubiKey/smartcard config, fwupd/TLP/UPower, and input remapping tools
- filesystem findings such as ELF executables, shebang scripts, desktop entries, systemd units, configs, secrets, stateful data, and location hints for `/opt`, `/usr/local`, `/srv`, and user-local paths

Package mapping and Nix option rendering are intentionally conservative. apt and common language CLI tools get static Nix candidates when known, including selected CLI aliases and case normalization; snap, flatpak, AppImage, Homebrew, secrets, stateful data, raw dotfiles, service unit bodies, and repository keys are reported without automatic Nix replacements by default.

## Development

```sh
make fmt-check
make vet
make test
make build
```

In restricted environments, `GOCACHE` may need to point at a writable directory. The Makefile defaults to `/tmp/codex-go-build`.

## Release

Versions use SemVer and annotated tags. Before tagging, add a `## [vX.Y.Z]` entry to `CHANGELOG.md` and run the same validation the release workflow runs:

```sh
make release-check VERSION=v0.1.0
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`make release-check` (`scripts/release-check.sh`) checks that `CHANGELOG.md` has a matching version heading, runs format/vet/test, builds Linux `amd64`/`arm64` archives with version, commit, and build-date metadata into `dist/`, and smoke-tests them — `linux-nixer version` and `linux-nixer version --full` included. Pushing a `v*` tag runs the release workflow, which calls the exact same script before creating checksums and a GitHub Release, so a clean local `make release-check` run is a strong signal the tag will release cleanly. Tags must match `vMAJOR.MINOR.PATCH` or a SemVer prerelease such as `v0.1.0-rc.1`.
