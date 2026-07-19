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

func TestDevOpsConfigScannerMarksSecretRiskConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "users:\n- token: super-secret\n")
	report := &model.ScanReport{}
	if err := (DevOpsConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) == 0 {
		t.Fatal("expected config item")
	}
	if report.Items[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("decision=%q, want migration-note", report.Items[0].Decision)
	}
	if len(report.Warnings) == 0 || report.Warnings[0].Source != "devops-config" || !strings.Contains(report.Warnings[0].Message, "secret-risk") {
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

func TestDevOpsConfigScannerFindsProviderConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "users:\n- token: super-secret\n")
	write(t, root, "/home/alice/.docker/config.json", `{"auths":{}}`)
	write(t, root, "/home/alice/.config/helm/repositories.yaml", "repositories: []\n")
	write(t, root, "/home/alice/.terraformrc", "credentials \"app.terraform.io\" {}\n")
	write(t, root, "/home/alice/.aws/config", "[default]\nregion=us-east-1\n")
	write(t, root, "/home/alice/.config/gcloud/configurations/config_default", "[core]\n")
	write(t, root, "/home/alice/.azure/config", "[cloud]\n")

	report := &model.ScanReport{}
	if err := (DevOpsConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Decision{}
	for _, item := range report.Items {
		seen[item.Path] = item.Decision
	}
	for _, path := range []string{
		"/home/alice/.kube/config",
		"/home/alice/.docker/config.json",
		"/home/alice/.config/helm/repositories.yaml",
		"/home/alice/.terraformrc",
		"/home/alice/.config/gcloud/configurations/config_default",
		"/home/alice/.azure/config",
	} {
		if seen[path] != model.DecisionMigrationNote {
			t.Fatalf("path %s decision=%q, want migration-note in %+v", path, seen[path], report.Items)
		}
	}
	if seen["/home/alice/.aws/config"] != model.DecisionCandidate {
		t.Fatalf("aws config should remain candidate in %+v", report.Items)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected secret-risk warnings, got %+v", report.Warnings)
	}
}

func TestProjectConfigScannerFindsProjectFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/project/package.json", "{}")
	write(t, root, "/home/alice/project/pyproject.toml", "[project]\nname='demo'\n")
	write(t, root, "/home/alice/project/requirements.txt", "ruff\n")
	write(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")
	write(t, root, "/home/alice/project/Cargo.toml", "[package]\n")
	write(t, root, "/home/alice/project/flake.nix", "{}")
	write(t, root, "/home/alice/project/.devcontainer/devcontainer.json", "{}")
	write(t, root, "/srv/app/package.json", "{}")
	write(t, root, "/srv/app/pyproject.toml", "[project]\n")
	write(t, root, "/srv/app/go.mod", "module example.com/app\n")
	write(t, root, "/srv/app/Cargo.toml", "[package]\n")
	write(t, root, "/srv/app/flake.nix", "{}")
	write(t, root, "/home/alice/project/.envrc", "use flake\n")
	write(t, root, "/home/alice/.gitconfig", "[user]\nname = Alice\n")
	write(t, root, "/etc/udev/rules.d/99-device.rules", `SUBSYSTEM=="usb"`)

	report := &model.ScanReport{}
	if err := (ProjectConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Decision{}
	for _, item := range report.Items {
		seen[item.Path] = item.Decision
	}
	for _, path := range []string{
		"/home/alice/project/package.json",
		"/home/alice/project/pyproject.toml",
		"/home/alice/project/requirements.txt",
		"/home/alice/project/go.mod",
		"/home/alice/project/Cargo.toml",
		"/home/alice/project/flake.nix",
		"/home/alice/project/.devcontainer/devcontainer.json",
		"/srv/app/package.json",
		"/srv/app/pyproject.toml",
		"/srv/app/go.mod",
		"/srv/app/Cargo.toml",
		"/srv/app/flake.nix",
	} {
		if seen[path] != model.DecisionCandidate {
			t.Fatalf("missing project config %s in %+v", path, report.Items)
		}
	}
	for _, path := range []string{"/home/alice/project/.envrc", "/home/alice/.gitconfig", "/etc/udev/rules.d/99-device.rules"} {
		if _, ok := seen[path]; ok {
			t.Fatalf("non-project config %s should not be handled by ProjectConfigScanner, got %+v", path, report.Items)
		}
	}
}

func TestDefaultRegistryUsesDedicatedConfigScanners(t *testing.T) {
	reg := DefaultRegistry()
	names := map[string]bool{}
	for _, scanner := range reg.scanners {
		names[scanner.Name()] = true
	}
	for _, want := range []string{"system-config", "devops-config", "project-config", "user-config", "desktop"} {
		if !names[want] {
			t.Fatalf("default registry missing %q in %+v", want, names)
		}
	}
	if names["config"] {
		t.Fatalf("default registry should not include legacy config scanner: %+v", names)
	}
}

func TestGitScannerFindsSourceMetadataAndHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/app/.git/config", "[remote \"origin\"]\n  url = https://example.com/app.git\n")
	write(t, root, "/home/alice/app/.git/HEAD", "ref: refs/heads/main\n")
	write(t, root, "/home/alice/app/.git/refs/heads/main", "abc123\n")
	write(t, root, "/home/alice/app/.gitmodules", "[submodule \"lib\"]\n")
	write(t, root, "/home/alice/app/flake.nix", "{}")
	write(t, root, "/home/alice/app/shell.nix", "{}")
	write(t, root, "/home/alice/app/justfile", "build:\n")
	write(t, root, "/home/alice/app/Taskfile.yml", "version: '3'\n")
	write(t, root, "/home/alice/app/docker-compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/compose.yaml", "services: {}\n")
	write(t, root, "/home/alice/app/.git/MERGE_HEAD", "def456\n")

	write(t, root, "/opt/tool/.git/config", "[remote \"origin\"]\n  url = git@example.com:tool.git\n")
	write(t, root, "/opt/tool/.git/HEAD", "deadbeef\n")
	write(t, root, "/opt/tool/Makefile", "all:\n")

	write(t, root, "/custom/source/.git/config", "[remote \"origin\"]\n  url = https://example.com/custom.git\n")
	write(t, root, "/custom/source/.git/HEAD", "ref: refs/heads/dev\n")
	write(t, root, "/custom/source/.git/refs/heads/dev", "feedface\n")
	write(t, root, "/custom/source/package.json", "{}")

	report := &model.ScanReport{}
	if err := (GitScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/custom"}}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.GitSource{}
	for _, source := range report.GitSources {
		seen[source.Path] = source
	}
	app := seen["/home/alice/app"]
	if app.Remote != "https://example.com/app.git" || app.Commit != "abc123" || !app.Dirty {
		t.Fatalf("unexpected app git source: %+v", app)
	}
	for _, want := range []string{"branch:main", "submodules", "flake.nix", "shell.nix", "justfile", "Taskfile.yml", "docker-compose.yml", "compose.yaml"} {
		if !contains(app.Build, want) {
			t.Fatalf("app missing build hint %q in %+v", want, app.Build)
		}
	}
	tool := seen["/opt/tool"]
	if tool.Remote != "git@example.com:tool.git" || tool.Commit != "deadbeef" || tool.Dirty {
		t.Fatalf("unexpected tool git source: %+v", tool)
	}
	if !contains(tool.Build, "Makefile") {
		t.Fatalf("tool missing Makefile hint: %+v", tool.Build)
	}
	custom := seen["/custom/source"]
	if custom.Remote != "https://example.com/custom.git" || custom.Commit != "feedface" || !contains(custom.Build, "branch:dev") || !contains(custom.Build, "package.json") {
		t.Fatalf("unexpected custom git source: %+v", custom)
	}
}

func TestSystemConfigScannerFindsOperationalConfigsAndServices(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/fstab", "UUID=demo / ext4 defaults 0 1\n")
	write(t, root, "/etc/hosts", "127.0.0.1 localhost\n")
	write(t, root, "/etc/sudoers", "root ALL=(ALL) ALL\n")
	write(t, root, "/etc/locale.conf", "LANG=en_US.UTF-8\n")
	write(t, root, "/etc/timezone", "UTC\n")
	write(t, root, "/etc/ssh/sshd_config", "PermitRootLogin no\n")
	write(t, root, "/etc/sysctl.conf", "vm.swappiness=10\n")
	write(t, root, "/etc/nftables.conf", "flush ruleset\n")
	write(t, root, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
	write(t, root, "/etc/default/ufw", "IPV6=yes\n")
	write(t, root, "/etc/netplan/01-net.yaml", "network: {}\n")
	write(t, root, "/etc/NetworkManager/NetworkManager.conf", "[main]\n")
	write(t, root, "/etc/NetworkManager/system-connections/home.nmconnection", "[wifi-security]\npsk=secret\n")
	write(t, root, "/etc/resolv.conf", "nameserver 1.1.1.1\n")
	write(t, root, "/etc/systemd/resolved.conf", "[Resolve]\n")
	write(t, root, "/etc/sysctl.d/99-local.conf", "fs.inotify.max_user_watches=1\n")
	write(t, root, "/etc/modprobe.d/local.conf", "options test value=1\n")
	write(t, root, "/etc/udev/rules.d/99-device.rules", `SUBSYSTEM=="usb"`)
	write(t, root, "/etc/logrotate.d/app", "/var/log/app/*.log {}\n")
	write(t, root, "/etc/nginx/sites-enabled/app", "server {}\n")
	write(t, root, "/etc/apache2/sites-enabled/app.conf", "<VirtualHost *:80>\n")
	write(t, root, "/etc/systemd/system/custom.service", "[Service]\n")
	write(t, root, "/etc/systemd/system/custom.timer", "[Timer]\n")
	write(t, root, "/home/alice/.config/systemd/user/user.service", "[Service]\n")
	write(t, root, "/etc/cron.d/job", "* * * * * root true\n")
	write(t, root, "/var/spool/cron/crontabs/alice", "* * * * * true\n")

	report := &model.ScanReport{}
	if err := (SystemConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Item{}
	for _, item := range report.Items {
		seen[item.Path] = item
	}
	for path, reason := range map[string]string{
		"/etc/fstab":           "filesystem mount configuration",
		"/etc/hosts":           "system configuration",
		"/etc/sudoers":         "privilege configuration",
		"/etc/locale.conf":     "localization configuration",
		"/etc/timezone":        "localization configuration",
		"/etc/ssh/sshd_config": "ssh daemon configuration",
		"/etc/sysctl.conf":     "kernel or device tuning",
		"/etc/nftables.conf":   "firewall configuration",
		"/etc/ufw/ufw.conf":    "firewall configuration",
		"/etc/default/ufw":     "firewall configuration",
		"/etc/netplan":         "network configuration",
		"/etc/NetworkManager/NetworkManager.conf":                  "network configuration",
		"/etc/resolv.conf":                                         "network configuration",
		"/etc/systemd/resolved.conf":                               "network configuration",
		"/etc/sysctl.d/99-local.conf":                              "kernel or device tuning",
		"/etc/modprobe.d/local.conf":                               "kernel or device tuning",
		"/etc/udev/rules.d/99-device.rules":                        "kernel or device tuning",
		"/etc/logrotate.d/app":                                     "log rotation configuration",
		"/etc/netplan/01-net.yaml":                                 "network configuration",
		"/etc/nginx/sites-enabled/app":                             "web server configuration",
		"/etc/apache2/sites-enabled/app.conf":                      "web server configuration",
		"/etc/NetworkManager/system-connections/home.nmconnection": "network connection profile may contain credentials",
	} {
		item, ok := seen[path]
		if !ok {
			t.Fatalf("missing %s in %+v", path, report.Items)
		}
		if item.Kind != "os-config" || item.Reason != reason {
			t.Fatalf("item %s=%+v, want os-config reason %q", path, item, reason)
		}
	}
	if seen["/etc/NetworkManager/system-connections/home.nmconnection"].Decision != model.DecisionMigrationNote {
		t.Fatalf("network secret should be migration note in %+v", report.Items)
	}
	services := map[string]string{}
	for _, service := range report.Services {
		services[service.Path] = service.Manager
	}
	for path, manager := range map[string]string{
		"/etc/systemd/system/custom.service":            "systemd",
		"/etc/systemd/system/custom.timer":              "systemd",
		"/home/alice/.config/systemd/user/user.service": "systemd",
		"/etc/cron.d/job":                               "cron",
		"/var/spool/cron/crontabs/alice":                "cron",
	} {
		if services[path] != manager {
			t.Fatalf("service %s manager=%q, want %q in %+v", path, services[path], manager, report.Services)
		}
	}
}

func TestUserConfigScannerFindsShellAndUserConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.bashrc", "alias ll='ls -la'\n")
	write(t, root, "/home/alice/.bash_profile", ". ~/.bashrc\n")
	write(t, root, "/home/alice/.profile", "export PATH=$HOME/.local/bin:$PATH\n")
	write(t, root, "/home/alice/.zshrc", "source ~/.zinit/bin/zinit.zsh\n")
	write(t, root, "/home/alice/.zprofile", "export EDITOR=nvim\n")
	write(t, root, "/home/alice/.config/fish/config.fish", "set -gx EDITOR nvim\n")
	write(t, root, "/home/alice/.config/fish/functions/f.fish", "function f\nend\n")
	write(t, root, "/home/alice/.config/fish/conf.d/path.fish", "fish_add_path ~/.local/bin\n")
	write(t, root, "/home/alice/.oh-my-zsh/.keep", "")
	write(t, root, "/home/alice/.zinit/.keep", "")
	write(t, root, "/home/alice/.antigen/.keep", "")
	writeMode(t, root, "/home/alice/.local/bin/tool", []byte("#!/bin/sh\n"), 0o755)
	write(t, root, "/home/alice/.pam_environment", "EDITOR=nvim\n")
	write(t, root, "/home/alice/.config/environment.d/editor.conf", "EDITOR=nvim\n")
	write(t, root, "/home/alice/.direnvrc", "layout_python\n")
	write(t, root, "/home/alice/project/.envrc", "use flake\n")
	write(t, root, "/home/alice/.gitconfig", "[user]\nname = Alice\n")
	write(t, root, "/home/alice/.gitignore_global", "*.swp\n")
	write(t, root, "/home/alice/.ssh/config", "Host example\n  HostName example.com\n")
	write(t, root, "/home/alice/.gnupg/gpg.conf", "use-agent\n")
	write(t, root, "/home/alice/.tmux.conf", "set -g mouse on\n")
	write(t, root, "/home/alice/.config/starship.toml", "[character]\n")

	report := &model.ScanReport{}
	if err := (UserConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, item := range report.Items {
		seen[item.Path] = item.Kind
		if item.Decision != model.DecisionCandidate {
			t.Fatalf("user config decision=%q, want candidate", item.Decision)
		}
	}
	for path, kind := range map[string]string{
		"/home/alice/.bashrc":                           "shell-config",
		"/home/alice/.bash_profile":                     "shell-config",
		"/home/alice/.profile":                          "shell-config",
		"/home/alice/.zshrc":                            "shell-config",
		"/home/alice/.zprofile":                         "shell-config",
		"/home/alice/.config/fish/config.fish":          "shell-config",
		"/home/alice/.config/fish/functions/f.fish":     "shell-config",
		"/home/alice/.config/fish/conf.d/path.fish":     "shell-config",
		"/home/alice/.oh-my-zsh":                        "shell-plugin",
		"/home/alice/.zinit":                            "shell-plugin",
		"/home/alice/.antigen":                          "shell-plugin",
		"/home/alice/.local/bin/tool":                   "user-bin",
		"/home/alice/.pam_environment":                  "shell-config",
		"/home/alice/.config/environment.d/editor.conf": "shell-config",
		"/home/alice/.direnvrc":                         "shell-config",
		"/home/alice/project/.envrc":                    "direnv",
		"/home/alice/.gitconfig":                        "user-config",
		"/home/alice/.gitignore_global":                 "user-config",
		"/home/alice/.ssh/config":                       "user-config",
		"/home/alice/.gnupg/gpg.conf":                   "user-config",
		"/home/alice/.tmux.conf":                        "user-config",
		"/home/alice/.config/starship.toml":             "user-config",
	} {
		if seen[path] != kind {
			t.Fatalf("path %s kind=%q, want %q in %+v", path, seen[path], kind, report.Items)
		}
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

func TestContainerScannerUsesInspectForRuntimeDetails(t *testing.T) {
	report := &model.ScanReport{}
	err := (ContainerScanner{}).Scan(context.Background(), Options{
		Root: "/",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case `docker ps -a --format {{json .}}`:
				return []byte(`{"Names":"web","Image":"nginx:1.27","Ports":"0.0.0.0:8080->80/tcp"}` + "\n"), nil
			case "docker inspect web":
				return []byte(`[{
					"Config":{"Image":"nginx:1.27","Env":["TOKEN=secret","MODE=prod"]},
					"RepoDigests":["nginx@sha256:demo"],
					"Mounts":[{"Type":"bind","Source":"/srv/web","Destination":"/app"}]
				}]`), nil
			case `podman ps -a --format {{json .}}`:
				return []byte(`{"Names":"db","Image":"postgres:16","Ports":""}` + "\n"), nil
			case "podman inspect db":
				return []byte(`[{
					"Config":{"Image":"postgres:16","Env":["POSTGRES_PASSWORD=secret"]},
					"RepoDigests":["postgres@sha256:demo"],
					"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIP":"127.0.0.1","HostPort":"5432"}]}},
					"Mounts":[{"Type":"volume","Source":"pgdata","Destination":"/var/lib/postgresql/data"}]
				}]`), nil
			default:
				return nil, errors.New("unexpected command: " + command)
			}
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Container{}
	for _, container := range report.Containers {
		seen[container.Runtime+":"+container.Name] = container
	}
	web := seen["docker:web"]
	if web.Image != "nginx:1.27" || web.Digest != "nginx@sha256:demo" || len(web.Mounts) != 1 || web.Mounts[0] != "bind:/srv/web:/app" {
		t.Fatalf("unexpected docker container: %+v", web)
	}
	if _, ok := web.Env["TOKEN"]; !ok {
		t.Fatalf("docker env keys missing TOKEN: %+v", web.Env)
	}
	if web.Env["TOKEN"] != "" {
		t.Fatalf("docker env value should be redacted: %+v", web.Env)
	}
	db := seen["podman:db"]
	if db.Image != "postgres:16" || db.Digest != "postgres@sha256:demo" || len(db.Ports) != 1 || db.Ports[0] != "127.0.0.1:5432->5432/tcp" {
		t.Fatalf("unexpected podman container: %+v", db)
	}
	if _, ok := db.Env["POSTGRES_PASSWORD"]; !ok || db.Env["POSTGRES_PASSWORD"] != "" {
		t.Fatalf("podman env key should be present with redacted value: %+v", db.Env)
	}
}

func TestContainerScannerMountedRootFindsComposeWithoutRuntimeCommands(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/app/compose.yaml", "services: {}\n")
	write(t, root, "/home/alice/app/compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/docker-compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/docker-compose.yaml", "services: {}\n")
	write(t, root, "/srv/app/docker-compose.yaml", "services: {}\n")

	report := &model.ScanReport{}
	called := false
	err := (ContainerScanner{}).Scan(context.Background(), Options{
		Root: root,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return nil, errors.New("runtime command should not run")
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("runtime command should not be called for mounted root")
	}
	seen := map[string]bool{}
	for _, container := range report.Containers {
		seen[container.Compose] = true
	}
	for _, want := range []string{
		"/home/alice/app/compose.yaml",
		"/home/alice/app/compose.yml",
		"/home/alice/app/docker-compose.yml",
		"/home/alice/app/docker-compose.yaml",
		"/srv/app/docker-compose.yaml",
	} {
		if !seen[want] {
			t.Fatalf("missing compose %s in %+v", want, report.Containers)
		}
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

func TestLanguageScannerFindsLanguageEcosystemHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.local/share/pnpm/global/5/node_modules/prettier/package.json", `{"name":"prettier","version":"3.0.0"}`)
	write(t, root, "/home/alice/.config/yarn/global/node_modules/yarn/package.json", `{"name":"yarn","version":"1.22.0"}`)
	write(t, root, "/home/alice/project/package.json", `{"packageManager":"pnpm@9.0.0"}`)
	write(t, root, "/home/alice/project/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	write(t, root, "/home/alice/project/pyproject.toml", "[project]\nname='demo'\n")
	write(t, root, "/home/alice/project/requirements.txt", "ruff\n")
	write(t, root, "/home/alice/project/poetry.lock", "# lock\n")
	write(t, root, "/home/alice/project/Pipfile", "[packages]\n")
	write(t, root, "/home/alice/project/uv.lock", "version = 1\n")
	write(t, root, "/home/alice/project/environment.yml", "name: demo\n")
	write(t, root, "/home/alice/project/Cargo.toml", "[package]\n")
	write(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")
	write(t, root, "/home/alice/project/Gemfile", "source 'https://rubygems.org'\n")
	write(t, root, "/srv/app/Gemfile", "source 'https://rubygems.org'\n")
	write(t, root, "/home/alice/miniconda3/envs/data/conda-meta/history", "")
	write(t, root, "/home/alice/.condarc", "channels:\n")
	write(t, root, "/home/alice/.tool-versions", "nodejs 22\n")
	write(t, root, "/home/alice/project/.node-version", "22\n")
	write(t, root, "/home/alice/.local/share/mise/config.toml", "")

	report := &model.ScanReport{}
	if err := (LanguageScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	assertPkgMapping(t, report.Languages.NPM, "prettier", "nodePackages.prettier")
	assertPkgMapping(t, report.Languages.NPM, "yarn", "yarn")
	if len(report.Languages.Conda) != 1 || report.Languages.Conda[0].Name != "data" || report.Languages.Conda[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("unexpected conda envs: %+v", report.Languages.Conda)
	}
	vms := map[string]bool{}
	for _, vm := range report.Languages.VMs {
		vms[vm.Name+"@"+vm.Path] = true
	}
	for _, want := range []string{"mise@/home/alice/.local/share/mise", ".tool-versions@/home/alice/.tool-versions", ".node-version@/home/alice/project/.node-version"} {
		if !vms[want] {
			t.Fatalf("missing version manager marker %s in %+v", want, report.Languages.VMs)
		}
	}
	items := map[string]model.Item{}
	for _, item := range report.Items {
		if item.Kind == "language-project" {
			items[item.Path] = item
		}
	}
	for _, path := range []string{
		"/home/alice/project/package.json",
		"/home/alice/project/pnpm-lock.yaml",
		"/home/alice/project/pyproject.toml",
		"/home/alice/project/requirements.txt",
		"/home/alice/project/poetry.lock",
		"/home/alice/project/Pipfile",
		"/home/alice/project/uv.lock",
		"/home/alice/project/environment.yml",
		"/home/alice/project/Cargo.toml",
		"/home/alice/project/go.mod",
		"/home/alice/project/Gemfile",
		"/srv/app/Gemfile",
		"/home/alice/.condarc",
	} {
		if items[path].Decision != model.DecisionCandidate {
			t.Fatalf("missing language project item %s in %+v", path, report.Items)
		}
	}
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
