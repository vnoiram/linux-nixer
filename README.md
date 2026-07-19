# linux-nixer

`linux-nixer` scans Debian/Ubuntu-like Linux environments and generates an editable NixOS + Home Manager flake.

The project is intentionally conservative: it detects a wide range of system state, but only turns high-confidence items into Nix automatically. Risky items such as secrets, keys, large stateful data, browser profiles, and cloud credentials are reported as migration notes instead of being embedded into generated Nix files.

Generated Nix settings only include findings marked `confirmed`. Findings left as `candidate` stay in reports and TODO comments until reviewed.

## Current status

This is an early implementation scaffold. It includes:

- Go CLI commands: `scan`, `review`, `generate`, `doctor`, `baseline create`
- Registry-based scanners for host/user metadata, apt, language tooling, Git sources, containers, common config files, and filesystem findings
- Dedicated package ecosystem scanners for snap, flatpak, AppImage, and Homebrew on Linux
- Baseline manifest creation for rootfs comparisons
- Nix flake project rendering
- Richer generated modules for services, containers, filesystem findings, and development project reports
- Confirmed-only rendering for system packages, Home Manager packages, and container runtime enables
- Shared conservative Nix package mapping for apt, npm, pipx/Python CLI, cargo, go-install, and gem findings
- Non-interactive review rules for confirming, excluding, or deferring findings
- Interactive review mode using only the Go standard library
- `doctor --vm` support for building the generated NixOS VM derivation
- Optional `doctor --boot` check for starting the generated VM script with a timeout
- Baseline IDs such as `ubuntu:24.04` resolved from local `baselines/` or user cache
- Unit and fixture-style tests, including seeded arbitrary-directory executable detection
- GitHub Actions CI and tag-based release workflow

## Usage

```sh
go build -o bin/linux-nixer ./cmd/linux-nixer

bin/linux-nixer scan --out scan.json
bin/linux-nixer review --scan scan.json --out reviewed.json --auto-safe
bin/linux-nixer generate --scan reviewed.json --out nix-config
bin/linux-nixer doctor --project nix-config
```

For fixture or mounted rootfs scans:

```sh
bin/linux-nixer scan --root /path/to/rootfs --include /random-seed-42 --out scan.json
```

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
- `reports/migration-report.md`
- `reports/dev-projects.md`

## Scanner domains

- apt/dpkg packages and apt sources
- snap, flatpak, AppImage, and Homebrew on Linux
- npm global packages and local node module metadata
- Python venv and pipx environments
- version managers such as asdf, nvm, pyenv, rbenv, sdkman, conda
- cargo, gem, and `go install` style user binaries
- Git checkouts under common source locations
- Docker/Podman containers and compose files
- systemd, cron, shell/git/ssh/gpg/devops config markers
- desktop markers, fonts, themes, autostart entries
- filesystem findings such as ELF executables, shebang scripts, desktop entries, systemd units, configs, secrets, and stateful data

Package mapping is intentionally conservative. apt and common language CLI tools get static Nix candidates when known; snap, flatpak, AppImage, and Homebrew findings are reported without automatic Nix replacements by default.

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
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Pushing a `v*` tag runs the release workflow, builds Linux `amd64` and `arm64` tarballs, creates checksums, and uploads them to a GitHub Release.
