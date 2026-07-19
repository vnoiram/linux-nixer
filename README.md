# linux-nixer

`linux-nixer` scans Debian/Ubuntu-like Linux environments and generates an editable NixOS + Home Manager flake.

The project is intentionally conservative: it detects a wide range of system state, but only turns high-confidence items into Nix automatically. Risky items such as secrets, keys, large stateful data, browser profiles, and cloud credentials are reported as migration notes instead of being embedded into generated Nix files.

Generated Nix settings only include findings marked `confirmed`. Findings left as `candidate` stay in reports and TODO comments until reviewed.

## Current status

This is an early implementation scaffold. It includes:

- Go CLI commands: `scan`, `review`, `generate`, `doctor`, `baseline create`
- Registry-based scanners for host/user metadata, groups, apt, language tooling, Git sources, containers, system config files, DevOps/project config, user shell settings, desktop settings, and filesystem findings
- Dedicated package ecosystem scanners for snap, flatpak, AppImage, and Homebrew on Linux
- Baseline manifest creation for rootfs comparisons
- Nix flake project rendering
- Richer generated modules and reports for package sources, services, containers, language ecosystems, filesystem findings, system config, DevOps config, user shell settings, desktop settings, and development projects
- Confirmed-only rendering for system packages, Home Manager packages, and container runtime enables
- Conservative Nix option rendering for detected users, safe shell enables, and selected confirmed Home Manager program enables
- Shared conservative Nix package mapping for apt, npm, pipx/Python CLI, cargo, go-install, and gem findings
- Non-interactive review rules for confirming, excluding, or deferring findings
- Interactive review mode using only the Go standard library
- Review summary output and pending-finding gates before generating Nix
- One-shot capture workflow for scan, auto-safe review, summary, and Nix generation
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
bin/linux-nixer review --scan scan.json --out reviewed.json --auto-safe
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
bin/linux-nixer generate --scan reviewed.json --out nix-config
bin/linux-nixer doctor --project nix-config
```

For fixture or mounted rootfs scans:

```sh
bin/linux-nixer scan --root /path/to/rootfs --include /random-seed-42 --out scan.json
bin/linux-nixer capture --root /path/to/rootfs --include /random-seed-42 --out linux-nixer-output
```

`capture` writes `scan.json`, `reviewed.json`, `summary.md`, and `nix-config/` under the output directory. It applies the same conservative auto-safe review as `review --auto-safe`; use the split `scan` and `review --interactive` flow when you want to approve findings manually before generating Nix.

Create a local baseline manifest:

```sh
mkdir -p baselines
bin/linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baselines/ubuntu-24.04.json
bin/linux-nixer scan --root /path/to/current-root --baseline ubuntu:24.04 --out scan.json
```

`--baseline` accepts either a JSON path or an ID such as `ubuntu:24.04`. IDs resolve to `baselines/ubuntu-24.04.json` in the current project first, then to the user cache under `linux-nixer/baselines/`.

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

Interactive review accepts `c` confirmed, `k` candidate, `t` todo, `m` migration-note, `x` excluded, `s` skip, and `q` quit. Secret-like and stateful findings cannot be confirmed interactively; they remain migration notes unless excluded.

Summarize reviewed decisions before generating Nix:

```sh
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
```

`--fail-on-pending` exits non-zero when `candidate` or `todo` findings remain. `migration-note` findings are treated as expected manual migration work and do not fail the gate.

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
- `reports/system-config.md`
- `reports/devops-config.md`
- `reports/dev-projects.md`
- `reports/user-config.md`
- `reports/desktop.md`

## Scanner domains

- apt/dpkg packages, manual install hints, apt repositories, keyrings, preferences, and apt config
- Linux users, login shells, home directories, system-user hints, supplementary groups, and privileged group membership
- snap, flatpak, AppImage, and Homebrew on Linux
- npm/pnpm/yarn global packages and local node package manager metadata
- Python venv, pipx, pyproject, requirements, Poetry, Pipenv, uv, and Conda environment markers
- version managers such as asdf, mise, nvm, fnm, volta, pyenv, rbenv, sdkman, and conda
- cargo, gem, `go install` style user binaries, and Rust/Go/Ruby project manifests
- Git checkouts under common source locations with remote, commit, branch, dirty, submodule, and build hints
- Docker/Podman containers, inspect metadata, and compose files
- systemd, cron, network, firewall, web server, and kernel/device tuning markers
- DevOps config markers such as Kubernetes, Docker client config, Helm, Terraform, AWS, GCP, and Azure
- shell/user settings such as bash, zsh, fish, profile/env files, direnv, git, ssh, gpg, tmux, starship, shell plugin trees, and `.local/bin` executables
- desktop environment markers, fonts, themes/icons, autostart entries, GNOME dconf dumps, KDE/i3/sway/input method config, and common terminal/editor settings
- filesystem findings such as ELF executables, shebang scripts, desktop entries, systemd units, configs, secrets, stateful data, and location hints for `/opt`, `/usr/local`, `/srv`, and user-local paths

Package mapping and Nix option rendering are intentionally conservative. apt and common language CLI tools get static Nix candidates when known; snap, flatpak, AppImage, Homebrew, secrets, stateful data, raw dotfiles, service unit bodies, and repository keys are reported without automatic Nix replacements by default.

## Development

```sh
make fmt-check
make vet
make test
make build
```

In restricted environments, `GOCACHE` may need to point at a writable directory. The Makefile defaults to `/tmp/codex-go-build`.

## Release

Versions use SemVer and annotated tags:

```sh
make build VERSION=v0.1.0
bin/linux-nixer version
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Pushing a `v*` tag runs the release workflow. Tags must match `vMAJOR.MINOR.PATCH` or a SemVer prerelease such as `v0.1.0-rc.1`. The workflow injects the tag into `linux-nixer version`, builds Linux `amd64` and `arm64` tarballs, smoke-tests the archives, creates checksums, and uploads them to a GitHub Release.
