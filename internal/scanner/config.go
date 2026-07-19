package scanner

import (
	"context"
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
		if existsWithSudo(ctx, opts, report, "config", path) {
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
	scanDevOpsConfigs(opts, report)
	scanProjectConfigs(opts, report)
	return nil
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
		report.Items = append(report.Items, model.Item{Kind: kind, Name: filepath.Base(path), Path: displayPath(opts.Root, path), Decision: decision, Reason: reason})
	}
}
