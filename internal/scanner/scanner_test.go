package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestAptScannerParsesInstalledPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

Package: removed
Status: deinstall ok config-files
Version: 1.0
`)

	report := &model.ScanReport{}
	if err := (AptScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Packages) != 1 {
		t.Fatalf("packages=%d, want 1", len(report.Packages))
	}
	if report.Packages[0].Name != "curl" || report.Packages[0].NixNames[0] != "curl" {
		t.Fatalf("unexpected package: %+v", report.Packages[0])
	}
}

func TestFilesystemDiffClassifiesSeededRandomLikeApps(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/random-seed-42/tools/fake-elf", append([]byte{0x7f, 'E', 'L', 'F'}, []byte("payload")...), 0o755)
	writeMode(t, root, "/random-seed-42/tools/script.py", []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o755)
	write(t, root, "/random-seed-42/app.desktop", "[Desktop Entry]\nName=Seeded\n")
	write(t, root, "/random-seed-42/seeded.service", "[Service]\nExecStart=/random-seed-42/tools/fake-elf\n")

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/random-seed-42"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]bool{}
	for _, finding := range report.FilesystemDiff {
		cats[finding.Category] = true
	}
	for _, want := range []string{"executable", "script", "desktop-entry", "service"} {
		if !cats[want] {
			t.Fatalf("missing category %q in %+v", want, report.FilesystemDiff)
		}
	}
}

func TestFilesystemDiffUsesBaselineManifest(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/usr/local/bin/same", []byte("#!/bin/sh\necho same\n"), 0o755)
	writeMode(t, root, "/usr/local/bin/new", []byte("#!/bin/sh\necho new\n"), 0o755)
	baseline := filepath.Join(root, "baseline.json")
	sum := sha256Hex(t, filepath.Join(root, "usr/local/bin/same"))
	if err := os.WriteFile(baseline, []byte(`{"files":[{"path":"/usr/local/bin/same","type":"script","mode":"-rwxr-xr-x","size":20,"sha256":"`+sum+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, BaselineID: baseline, Includes: []string{"/usr/local/bin"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/usr/local/bin/same" {
			t.Fatalf("unchanged baseline file should be skipped: %+v", report.FilesystemDiff)
		}
	}
	foundNew := false
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/usr/local/bin/new" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Fatalf("new file missing: %+v", report.FilesystemDiff)
	}
}

func TestConfigScannerMarksSecretRiskDevOpsConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "users:\n- token: super-secret\n")
	report := &model.ScanReport{}
	if err := (ConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) == 0 {
		t.Fatal("expected config item")
	}
	if report.Items[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("decision=%q, want migration-note", report.Items[0].Decision)
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0].Message, "secret-risk") {
		t.Fatalf("expected secret warning, got %+v", report.Warnings)
	}
}

func TestConfigScannerFindsOperationalAndProjectConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/udev/rules.d/99-device.rules", `SUBSYSTEM=="usb"`)
	write(t, root, "/etc/NetworkManager/system-connections/home.nmconnection", "[wifi-security]\npsk=secret\n")
	write(t, root, "/home/alice/project/pyproject.toml", "[project]\nname='demo'\n")
	write(t, root, "/home/alice/project/.devcontainer/devcontainer.json", "{}")

	report := &model.ScanReport{}
	if err := (ConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Decision{}
	for _, item := range report.Items {
		seen[item.Path] = item.Decision
	}
	if seen["/etc/udev/rules.d/99-device.rules"] != model.DecisionCandidate {
		t.Fatalf("missing udev rule in %+v", report.Items)
	}
	if seen["/etc/NetworkManager/system-connections/home.nmconnection"] != model.DecisionMigrationNote {
		t.Fatalf("network secret should be migration note in %+v", report.Items)
	}
	if seen["/home/alice/project/pyproject.toml"] != model.DecisionCandidate {
		t.Fatalf("missing project config in %+v", report.Items)
	}
	if seen["/home/alice/project/.devcontainer/devcontainer.json"] != model.DecisionCandidate {
		t.Fatalf("missing devcontainer config in %+v", report.Items)
	}
}

func TestPackageEcosystemScannerFindsFlatpakAppImageAndHomebrew(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/flatpak/app/org.example.App/current/active/files/bin/app", "")
	writeMode(t, root, "/home/alice/Applications/Tool.AppImage", []byte("appimage"), 0o755)
	write(t, root, "/home/linuxbrew/.linuxbrew/Cellar/hello/1.0/INSTALL_RECEIPT.json", "{}")

	report := &model.ScanReport{}
	if err := (PackageEcosystemScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, pkg := range report.Packages {
		seen[pkg.Manager+":"+pkg.Name] = true
		if pkg.Manager == "appimage" && len(pkg.NixNames) != 0 {
			t.Fatalf("appimage should not get nix mapping: %+v", pkg)
		}
	}
	for _, want := range []string{"flatpak:org.example.App", "appimage:Tool", "homebrew:hello"} {
		if !seen[want] {
			t.Fatalf("missing %s in %+v", want, report.Packages)
		}
	}
}

func TestLanguageScannerAddsNixCandidatesForKnownCLIs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/local/lib/node_modules/typescript/package.json", `{"name":"typescript","version":"5.0.0"}`)
	write(t, root, "/home/alice/.local/pipx/venvs/ruff/pipx_metadata.json", `{}`)
	writeMode(t, root, "/home/alice/.cargo/bin/starship", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/go/bin/gopls", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/.gem/ruby/3.3.0/bin/bundler", []byte("#!/bin/sh\n"), 0o755)

	report := &model.ScanReport{}
	if err := (LanguageScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	assertPkgMapping(t, report.Languages.NPM, "typescript", "nodePackages.typescript")
	if len(report.Languages.Python) != 1 {
		t.Fatalf("python envs=%d, want 1", len(report.Languages.Python))
	}
	assertPkgMapping(t, report.Languages.Python[0].Packages, "ruff", "ruff")
	assertPkgMapping(t, report.Languages.Cargo, "starship", "starship")
	assertPkgMapping(t, report.Languages.Go, "gopls", "gopls")
	assertPkgMapping(t, report.Languages.Gem, "bundler", "bundler")
}

func assertPkgMapping(t *testing.T, packages []model.Package, name, want string) {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name {
			if len(pkg.NixNames) != 1 || pkg.NixNames[0] != want {
				t.Fatalf("%s nixNames=%v, want [%s]", name, pkg.NixNames, want)
			}
			return
		}
	}
	t.Fatalf("package %s missing from %+v", name, packages)
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	writeMode(t, root, path, []byte(content), 0o644)
}

func writeMode(t *testing.T, root, path string, content []byte, mode os.FileMode) {
	t.Helper()
	abs := filepath.Join(root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, content, mode); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
