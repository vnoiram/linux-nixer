# linux-nixer

`linux-nixer` scans Debian/Ubuntu-like Linux environments and generates an editable NixOS + Home Manager flake.

The project is intentionally conservative: it detects a wide range of system state, but only turns high-confidence items into Nix automatically. Risky items such as secrets, keys, large stateful data, browser profiles, and cloud credentials are reported as migration notes instead of being embedded into generated Nix files.

## Current status

This is an early implementation scaffold. It includes:

- Go CLI commands: `scan`, `review`, `generate`, `doctor`, `baseline create`
- Registry-based scanners for host/user metadata, apt, language tooling, Git sources, containers, common config files, and filesystem findings
- Baseline manifest creation for rootfs comparisons
- Nix flake project rendering
- Unit and fixture-style tests, including seeded arbitrary-directory executable detection
- GitHub Actions CI and tag-based release workflow

## Usage

```sh
go build -o bin/linux-nixer ./cmd/linux-nixer

bin/linux-nixer scan --out scan.json
bin/linux-nixer review --scan scan.json --out reviewed.json
bin/linux-nixer generate --scan reviewed.json --out nix-config
bin/linux-nixer doctor --project nix-config
```

For fixture or mounted rootfs scans:

```sh
bin/linux-nixer scan --root /path/to/rootfs --include /random-seed-42 --out scan.json
```

Create a local baseline manifest:

```sh
bin/linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baselines/ubuntu-24.04.json
```

## Scanner domains

- apt/dpkg packages and apt sources
- npm global packages and local node module metadata
- Python venv and pipx environments
- version managers such as asdf, nvm, pyenv, rbenv, sdkman, conda
- cargo, gem, and `go install` style user binaries
- Git checkouts under common source locations
- Docker/Podman containers and compose files
- systemd, cron, shell/git/ssh/gpg/devops config markers
- desktop markers, fonts, themes, autostart entries
- filesystem findings such as ELF executables, shebang scripts, desktop entries, systemd units, configs, secrets, and stateful data

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
