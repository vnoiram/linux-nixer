package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func TestAptScannerUsesSudoFallbackForStatus(t *testing.T) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		t.Skip("host dpkg status is readable; apt sudo fallback path cannot be forced deterministically")
	}
	report := &model.ScanReport{}
	called := false
	err := (AptScanner{}).Scan(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "sudo" || strings.Join(args, " ") != "cat /var/lib/dpkg/status" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("Package: curl\nStatus: install ok installed\nVersion: 8.0\n\n"), nil
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("sudo fallback runner was not called")
	}
	if len(report.Packages) != 1 || report.Packages[0].Name != "curl" {
		t.Fatalf("unexpected packages: %+v", report.Packages)
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0].Message, "sudo fallback used") {
		t.Fatalf("missing sudo warning: %+v", report.Warnings)
	}
}

func TestReadFileUsesSudoFallback(t *testing.T) {
	report := &model.ScanReport{}
	called := false
	got, err := readFile(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "sudo" || strings.Join(args, " ") != "cat /definitely-missing-linux-nixer-test" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("fallback"), nil
		},
	}, report, "test", "/definitely-missing-linux-nixer-test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fallback" || !called {
		t.Fatalf("fallback got=%q called=%v", got, called)
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

func TestExistsWithSudoUsesSudoFallback(t *testing.T) {
	report := &model.ScanReport{}
	got := existsWithSudo(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "sudo" && strings.Join(args, " ") == "test -e /definitely-missing-linux-nixer-test" {
				return []byte{}, nil
			}
			return nil, errors.New("not found")
		},
	}, report, "test", "/definitely-missing-linux-nixer-test")
	if !got {
		t.Fatal("expected sudo fallback existence check to succeed")
	}
}

func TestSudoFallbackDisabledForMountedRootfs(t *testing.T) {
	root := t.TempDir()
	report := &model.ScanReport{}
	called := false
	_, err := readFile(context.Background(), Options{
		Root:    root,
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return []byte("secret"), nil
		},
	}, report, "test", "/missing")
	if err == nil {
		t.Fatal("expected normal read error")
	}
	if called {
		t.Fatal("sudo runner should not be called for mounted rootfs")
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

func TestDesktopScannerFindsMarkersAssetsAndConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/share/gnome/.keep", "")
	write(t, root, "/home/alice/.local/share/fonts/demo.ttf", "font")
	write(t, root, "/home/alice/.themes/demo/index.theme", "[Theme]\n")
	write(t, root, "/home/alice/.config/autostart/tool.desktop", "[Desktop Entry]\n")
	write(t, root, "/home/alice/.config/kdeglobals", "[KDE]\n")
	write(t, root, "/home/alice/.config/kwinrc", "[KWin]\n")
	write(t, root, "/home/alice/.config/i3/config", "bindsym Mod4+Enter exec alacritty\n")
	write(t, root, "/home/alice/.config/sway/config", "set $mod Mod4\n")
	write(t, root, "/home/alice/.config/fcitx5/profile", "[Groups]\n")
	write(t, root, "/home/alice/.config/ibus/bus", "")
	write(t, root, "/home/alice/.config/alacritty/alacritty.toml", "[window]\n")
	write(t, root, "/home/alice/.config/kitty/kitty.conf", "font_size 12\n")
	write(t, root, "/home/alice/.config/Code/User/settings.json", "{}")
	write(t, root, "/home/alice/.config/nvim/init.lua", "vim.opt.number = true\n")
	write(t, root, "/home/alice/.vimrc", "set number\n")

	report := &model.ScanReport{}
	if err := (DesktopScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if report.Desktop.Environment != "gnome" {
		t.Fatalf("environment=%q, want gnome", report.Desktop.Environment)
	}
	if len(report.Desktop.Fonts) != 1 || report.Desktop.Fonts[0] != "/home/alice/.local/share/fonts/demo.ttf" {
		t.Fatalf("unexpected fonts: %+v", report.Desktop.Fonts)
	}
	if len(report.Desktop.Themes) != 1 || report.Desktop.Themes[0] != "/home/alice/.themes/demo" {
		t.Fatalf("unexpected themes: %+v", report.Desktop.Themes)
	}
	if len(report.Desktop.Autostart) != 1 || report.Desktop.Autostart[0].Path != "/home/alice/.config/autostart/tool.desktop" {
		t.Fatalf("unexpected autostart: %+v", report.Desktop.Autostart)
	}
	seen := map[string]bool{}
	for _, item := range report.Items {
		if item.Kind == "desktop-config" {
			seen[item.Path] = true
			if item.Decision != model.DecisionCandidate {
				t.Fatalf("desktop config decision=%q, want candidate", item.Decision)
			}
		}
	}
	for _, want := range []string{
		"/home/alice/.config/kdeglobals",
		"/home/alice/.config/kwinrc",
		"/home/alice/.config/i3/config",
		"/home/alice/.config/sway/config",
		"/home/alice/.config/fcitx5/profile",
		"/home/alice/.config/ibus/bus",
		"/home/alice/.config/alacritty/alacritty.toml",
		"/home/alice/.config/kitty/kitty.conf",
		"/home/alice/.config/Code/User/settings.json",
		"/home/alice/.config/nvim/init.lua",
		"/home/alice/.vimrc",
	} {
		if !seen[want] {
			t.Fatalf("missing desktop config %q in %+v", want, report.Items)
		}
	}
}

func TestDesktopScannerDconfUsesRunnerOnHostRoot(t *testing.T) {
	report := &model.ScanReport{}
	called := false
	err := (DesktopScanner{}).Scan(context.Background(), Options{
		Root: "/",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "dconf" || strings.Join(args, " ") != "dump /" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("[org/gnome/desktop/interface]\ncolor-scheme='prefer-dark'\n"), nil
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected dconf runner to be called")
	}
	if len(report.Desktop.Dconf) != 2 || report.Desktop.Dconf[1] != "color-scheme='prefer-dark'" {
		t.Fatalf("unexpected dconf dump: %+v", report.Desktop.Dconf)
	}
}

func TestDesktopScannerDoesNotRunDconfForMountedRoot(t *testing.T) {
	root := t.TempDir()
	report := &model.ScanReport{}
	called := false
	err := (DesktopScanner{}).Scan(context.Background(), Options{
		Root: root,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return nil, errors.New("should not run")
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("dconf runner should not be called for mounted root")
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
