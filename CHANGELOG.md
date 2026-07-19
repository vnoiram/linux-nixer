# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

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
- CI and tag-based release workflow.
