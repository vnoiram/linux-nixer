package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type ConfigScanner struct{}

func (ConfigScanner) Name() string { return "config" }

func (ConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	for _, path := range []string{
		"/etc/fstab",
		"/etc/hosts",
		"/etc/sudoers",
		"/etc/locale.conf",
		"/etc/timezone",
		"/etc/ssh/sshd_config",
		"/etc/sysctl.conf",
		"/etc/nftables.conf",
		"/etc/ufw/ufw.conf",
		"/etc/default/ufw",
		"/etc/netplan",
		"/etc/NetworkManager/NetworkManager.conf",
		"/etc/resolv.conf",
		"/etc/systemd/resolved.conf",
	} {
		if exists(opts.Root, path) {
			report.Items = append(report.Items, model.Item{Kind: "os-config", Name: filepath.Base(path), Path: path, Decision: model.DecisionCandidate})
		}
	}
	for _, pattern := range []string{
		"/etc/sysctl.d/*.conf",
		"/etc/modprobe.d/*.conf",
		"/etc/udev/rules.d/*.rules",
		"/etc/logrotate.d/*",
		"/etc/netplan/*.yaml",
		"/etc/NetworkManager/system-connections/*",
		"/etc/nginx/sites-enabled/*",
		"/etc/apache2/sites-enabled/*",
	} {
		for _, path := range glob(opts.Root, pattern) {
			decision := model.DecisionCandidate
			reason := ""
			if strings.Contains(path, "/NetworkManager/system-connections/") {
				decision = model.DecisionMigrationNote
				reason = "network connection profile may contain credentials"
			}
			report.Items = append(report.Items, model.Item{Kind: "os-config", Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: decision, Reason: reason})
		}
	}
	for _, pattern := range []string{"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/home/*/.config/systemd/user/*.service"} {
		for _, path := range glob(opts.Root, pattern) {
			report.Services = append(report.Services, model.Service{Manager: "systemd", Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
		}
	}
	for _, pattern := range []string{"/etc/cron.d/*", "/var/spool/cron/crontabs/*"} {
		for _, path := range glob(opts.Root, pattern) {
			report.Services = append(report.Services, model.Service{Manager: "cron", Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
		}
	}
	for _, pattern := range []string{"/home/*/.ssh/config", "/home/*/.gitconfig", "/home/*/.gnupg/gpg.conf", "/home/*/.config/starship.toml", "/home/*/.tmux.conf"} {
		for _, path := range glob(opts.Root, pattern) {
			report.Items = append(report.Items, model.Item{Kind: "user-config", Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
		}
	}
	for _, pattern := range []string{"/home/*/.config/autostart/*.desktop"} {
		for _, path := range glob(opts.Root, pattern) {
			report.Desktop.Autostart = append(report.Desktop.Autostart, model.FileFinding{Path: displayPath(opts.Root, path), Type: "desktop-entry", Category: "desktop-autostart", Decision: model.DecisionCandidate})
		}
	}
	scanDesktopMarkers(opts, report)
	scanDevOpsConfigs(opts, report)
	scanProjectConfigs(opts, report)
	return nil
}

func scanDesktopMarkers(opts Options, report *model.ScanReport) {
	if exists(opts.Root, "/usr/bin/gnome-shell") || exists(opts.Root, "/usr/share/gnome") {
		report.Desktop.Environment = "gnome"
	}
	if exists(opts.Root, "/usr/bin/plasmashell") || exists(opts.Root, "/usr/share/plasma") {
		report.Desktop.Environment = "kde"
	}
	for _, path := range glob(opts.Root, "/usr/share/fonts/*", "/home/*/.local/share/fonts/*") {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			report.Desktop.Fonts = append(report.Desktop.Fonts, displayPath(opts.Root, path))
		}
	}
	for _, path := range glob(opts.Root, "/usr/share/themes/*", "/home/*/.themes/*", "/usr/share/icons/*", "/home/*/.icons/*") {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			report.Desktop.Themes = append(report.Desktop.Themes, displayPath(opts.Root, path))
		}
	}
}

func scanDevOpsConfigs(opts Options, report *model.ScanReport) {
	for _, pattern := range []string{"/home/*/.kube/config", "/home/*/.docker/config.json", "/home/*/.config/helm/repositories.yaml", "/home/*/.terraformrc", "/home/*/.aws/config", "/home/*/.config/gcloud/configurations/*", "/home/*/.azure/config"} {
		for _, path := range glob(opts.Root, pattern) {
			kind := "devops-config"
			secretRisk := hasAnySuffix(path, ".json", "config")
			decision := model.DecisionMigrationNote
			if strings.Contains(path, ".aws/config") {
				secretRisk = false
				decision = model.DecisionCandidate
			}
			report.Items = append(report.Items, model.Item{Kind: kind, Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: decision, Reason: "credentials are excluded by default"})
			if secretRisk {
				report.Warnings = append(report.Warnings, model.Warning{Source: "config", Message: "secret-risk config detected: " + displayPath(opts.Root, path)})
			}
		}
	}
}

func scanProjectConfigs(opts Options, report *model.ScanReport) {
	patterns := []string{
		"/home/*/**/package.json",
		"/home/*/**/pyproject.toml",
		"/home/*/**/requirements.txt",
		"/home/*/**/go.mod",
		"/home/*/**/Cargo.toml",
		"/home/*/**/flake.nix",
		"/home/*/**/.envrc",
		"/home/*/**/.devcontainer/devcontainer.json",
		"/srv/**/package.json",
		"/srv/**/pyproject.toml",
		"/srv/**/go.mod",
		"/srv/**/Cargo.toml",
		"/srv/**/flake.nix",
	}
	for _, path := range recursiveGlob(opts.Root, patterns...) {
		kind := "dev-project"
		decision := model.DecisionCandidate
		reason := "project dependency or development environment file"
		if filepath.Base(path) == ".envrc" {
			kind = "direnv"
		}
		report.Items = append(report.Items, model.Item{Kind: kind, Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: decision, Reason: reason})
	}
}
