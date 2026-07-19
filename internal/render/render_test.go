package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestProjectRendersFlakeAndReport(t *testing.T) {
	out := t.TempDir()
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Host:          model.Host{Hostname: "demo", Distro: "ubuntu", Release: "24.04"},
		Packages: []model.Package{{
			Manager:  "apt",
			Name:     "curl",
			NixNames: []string{"curl"},
			Decision: model.DecisionConfirmed,
		}},
	}
	if err := Project(out, report); err != nil {
		t.Fatal(err)
	}
	flake, err := os.ReadFile(filepath.Join(out, "flake.nix"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(flake), "nixosConfigurations.demo") {
		t.Fatalf("flake missing host: %s", flake)
	}
	cfg, err := os.ReadFile(filepath.Join(out, "hosts/generated/configuration.nix"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "pkgs.curl") {
		t.Fatalf("configuration missing package: %s", cfg)
	}
}

func TestProjectUsesPrimaryUserAndSafeHostAttr(t *testing.T) {
	out := t.TempDir()
	report := model.ScanReport{
		Host: model.Host{Hostname: "123 demo.host"},
		Users: []model.User{
			{Name: "daemon", Home: "/usr/sbin", System: true},
			{Name: "alice", Home: "/home/alice"},
		},
	}
	if err := Project(out, report); err != nil {
		t.Fatal(err)
	}
	flake, err := os.ReadFile(filepath.Join(out, "flake.nix"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(flake), "nixosConfigurations.host_123_demo_host") {
		t.Fatalf("flake missing sanitized host attr: %s", flake)
	}
	if !strings.Contains(string(flake), `home-manager.users."alice"`) {
		t.Fatalf("flake missing primary user: %s", flake)
	}
	home, err := os.ReadFile(filepath.Join(out, "users/home.nix"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(home), `home.homeDirectory = "/home/alice";`) {
		t.Fatalf("home missing primary home: %s", home)
	}
}

func TestProjectRendersRicherModulesAndReports(t *testing.T) {
	out := t.TempDir()
	report := model.ScanReport{
		Host: model.Host{Hostname: "demo"},
		Services: []model.Service{
			{Manager: "systemd", Name: "custom.service", Path: "/etc/systemd/system/custom.service", Decision: model.DecisionCandidate},
			{Manager: "cron", Name: "excluded", Path: "/etc/cron.d/excluded", Decision: model.DecisionExcluded},
		},
		Containers: []model.Container{
			{Runtime: "compose", Compose: "/srv/app/compose.yml", Decision: model.DecisionCandidate},
			{Runtime: "podman", Name: "db", Image: "postgres:16", Digest: "postgres@sha256:demo", Ports: []string{"127.0.0.1:5432->5432/tcp"}, Mounts: []string{"volume:pgdata:/var/lib/postgresql/data"}, Env: map[string]string{"POSTGRES_PASSWORD": ""}, Decision: model.DecisionConfirmed},
			{Runtime: "docker", Name: "excluded", Image: "redis:7", Env: map[string]string{"REDIS_PASSWORD": "secret"}, Decision: model.DecisionExcluded},
		},
		Items: []model.Item{
			{Kind: "dev-project", Path: "/home/alice/app/pyproject.toml", Decision: model.DecisionCandidate, Reason: "project dependency or development environment file"},
			{Kind: "os-config", Name: "99-device.rules", Path: "/etc/udev/rules.d/99-device.rules", Decision: model.DecisionCandidate, Reason: "kernel or device tuning"},
			{Kind: "os-config", Name: "home.nmconnection", Path: "/etc/NetworkManager/system-connections/home.nmconnection", Decision: model.DecisionMigrationNote, Reason: "network connection profile may contain credentials"},
			{Kind: "os-config", Name: "app", Path: "/etc/nginx/sites-enabled/app", Decision: model.DecisionCandidate, Reason: "web server configuration"},
			{Kind: "os-config", Name: "ufw.conf", Path: "/etc/ufw/ufw.conf", Decision: model.DecisionExcluded, Reason: "firewall configuration"},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.kube/config", Decision: model.DecisionMigrationNote, Reason: "kubernetes configuration may contain credentials"},
			{Kind: "devops-config", Name: "config.json", Path: "/home/alice/.docker/config.json", Decision: model.DecisionMigrationNote, Reason: "docker client configuration may contain credentials"},
			{Kind: "devops-config", Name: "repositories.yaml", Path: "/home/alice/.config/helm/repositories.yaml", Decision: model.DecisionMigrationNote, Reason: "helm repository configuration may contain credentials"},
			{Kind: "devops-config", Name: ".terraformrc", Path: "/home/alice/.terraformrc", Decision: model.DecisionMigrationNote, Reason: "terraform CLI configuration may contain credentials"},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.aws/config", Decision: model.DecisionCandidate, Reason: "aws CLI configuration"},
			{Kind: "devops-config", Name: "config_default", Path: "/home/alice/.config/gcloud/configurations/config_default", Decision: model.DecisionMigrationNote, Reason: "gcloud configuration may contain credentials"},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.azure/config", Decision: model.DecisionMigrationNote, Reason: "azure CLI configuration may contain credentials"},
			{Kind: "devops-config", Name: "excluded", Path: "/home/alice/.kube/excluded", Decision: model.DecisionExcluded, Reason: "kubernetes configuration may contain credentials"},
			{Kind: "user-config", Path: "/home/alice/.gitconfig", Decision: model.DecisionCandidate},
			{Kind: "shell-config", Name: ".zshrc", Path: "/home/alice/.zshrc", Decision: model.DecisionCandidate, Reason: "shell or login environment configuration"},
			{Kind: "shell-plugin", Name: ".oh-my-zsh", Path: "/home/alice/.oh-my-zsh", Decision: model.DecisionCandidate, Reason: "shell plugin manager or plugin tree"},
			{Kind: "user-bin", Name: "tool", Path: "/home/alice/.local/bin/tool", Decision: model.DecisionCandidate, Reason: "user-local executable"},
			{Kind: "direnv", Name: ".envrc", Path: "/home/alice/app/.envrc", Decision: model.DecisionCandidate, Reason: "direnv project environment file"},
			{Kind: "desktop-config", Name: "settings.json", Path: "/home/alice/.config/Code/User/settings.json", Decision: model.DecisionCandidate, Reason: "desktop environment configuration"},
		},
		Desktop: model.Desktop{
			Environment: "gnome",
			Fonts:       []string{"/home/alice/.local/share/fonts/demo.ttf"},
			Themes:      []string{"/home/alice/.themes/demo"},
			Autostart: []model.FileFinding{
				{Path: "/home/alice/.config/autostart/tool.desktop", Decision: model.DecisionCandidate},
			},
			Dconf: []string{"[org/gnome/desktop/interface]", "color-scheme='prefer-dark'"},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/usr/local/bin/tool", Category: "script", Reason: "shebang script", Decision: model.DecisionCandidate},
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true, Decision: model.DecisionMigrationNote},
			{Path: "/tmp/excluded", Category: "script", Decision: model.DecisionExcluded},
		},
	}
	if err := Project(out, report); err != nil {
		t.Fatal(err)
	}

	cfg := readFile(t, out, "hosts/generated/configuration.nix")
	for _, want := range []string{"../../modules/services.nix", "../../modules/filesystem-findings.nix"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("configuration missing import %q:\n%s", want, cfg)
		}
	}
	services := readFile(t, out, "modules/services.nix")
	if !strings.Contains(services, "custom.service") || !strings.Contains(services, "99-device.rules") {
		t.Fatalf("services module missing service/config TODOs:\n%s", services)
	}
	if strings.Contains(services, "excluded") || strings.Contains(services, "ufw.conf") {
		t.Fatalf("services module included excluded service:\n%s", services)
	}
	systemConfig := readFile(t, out, "reports/system-config.md")
	for _, want := range []string{"Kernel and devices", "/etc/udev/rules.d/99-device.rules", "Network", "/etc/NetworkManager/system-connections/home.nmconnection", "Web servers", "/etc/nginx/sites-enabled/app", "Services", "custom.service"} {
		if !strings.Contains(systemConfig, want) {
			t.Fatalf("system config report missing %q:\n%s", want, systemConfig)
		}
	}
	if strings.Contains(systemConfig, "excluded") || strings.Contains(systemConfig, "ufw.conf") {
		t.Fatalf("system config report included excluded entries:\n%s", systemConfig)
	}
	devopsConfig := readFile(t, out, "reports/devops-config.md")
	for _, want := range []string{"Kubernetes", "/home/alice/.kube/config", "Docker", "/home/alice/.docker/config.json", "Helm", "/home/alice/.config/helm/repositories.yaml", "Terraform", "/home/alice/.terraformrc", "AWS", "/home/alice/.aws/config", "GCP", "/home/alice/.config/gcloud/configurations/config_default", "Azure", "/home/alice/.azure/config"} {
		if !strings.Contains(devopsConfig, want) {
			t.Fatalf("devops config report missing %q:\n%s", want, devopsConfig)
		}
	}
	if strings.Contains(devopsConfig, "super-secret") || strings.Contains(devopsConfig, "excluded") {
		t.Fatalf("devops config report leaked raw secret or excluded entry:\n%s", devopsConfig)
	}
	containers := readFile(t, out, "modules/containers.nix")
	if !strings.Contains(containers, "virtualisation.docker.enable = false;") {
		t.Fatalf("containers module should not enable docker for candidate compose:\n%s", containers)
	}
	if !strings.Contains(containers, "virtualisation.podman.enable = true;") {
		t.Fatalf("containers module should enable podman:\n%s", containers)
	}
	if !strings.Contains(containers, "/srv/app/compose.yml") || !strings.Contains(containers, "postgres:16") {
		t.Fatalf("containers module missing TODOs:\n%s", containers)
	}
	containerReport := readFile(t, out, "reports/containers.md")
	for _, want := range []string{"Runtime containers", "podman container `db` image `postgres:16`", "postgres@sha256:demo", "127.0.0.1:5432->5432/tcp", "volume:pgdata:/var/lib/postgresql/data", "POSTGRES_PASSWORD", "Compose files", "/srv/app/compose.yml"} {
		if !strings.Contains(containerReport, want) {
			t.Fatalf("container report missing %q:\n%s", want, containerReport)
		}
	}
	if strings.Contains(containerReport, "secret") || strings.Contains(containerReport, "redis:7") {
		t.Fatalf("container report leaked env value or excluded container:\n%s", containerReport)
	}
	fs := readFile(t, out, "modules/filesystem-findings.nix")
	if !strings.Contains(fs, "/usr/local/bin/tool") {
		t.Fatalf("filesystem module missing script finding:\n%s", fs)
	}
	if strings.Contains(fs, "id_ed25519") || strings.Contains(fs, "/tmp/excluded") {
		t.Fatalf("filesystem module leaked secret/excluded finding:\n%s", fs)
	}
	dev := readFile(t, out, "reports/dev-projects.md")
	if !strings.Contains(dev, "/home/alice/app/pyproject.toml") || !strings.Contains(dev, "/home/alice/app/.envrc") {
		t.Fatalf("dev project report missing project:\n%s", dev)
	}
	home := readFile(t, out, "users/home.nix")
	for _, want := range []string{"/home/alice/.gitconfig", "/home/alice/.zshrc", "/home/alice/.oh-my-zsh", "/home/alice/.local/bin/tool", "/home/alice/app/.envrc", "/home/alice/.config/Code/User/settings.json"} {
		if !strings.Contains(home, want) {
			t.Fatalf("home module missing TODO %q:\n%s", want, home)
		}
	}
	if strings.Contains(home, "alias ll") {
		t.Fatalf("home module should not render raw config content:\n%s", home)
	}
	userConfig := readFile(t, out, "reports/user-config.md")
	for _, want := range []string{"Shell configuration", "/home/alice/.zshrc", "Shell plugins", "/home/alice/.oh-my-zsh", "User-local executables", "/home/alice/.local/bin/tool", "User tool configuration", "/home/alice/.gitconfig", "Direnv", "/home/alice/app/.envrc"} {
		if !strings.Contains(userConfig, want) {
			t.Fatalf("user config report missing %q:\n%s", want, userConfig)
		}
	}
	if strings.Contains(userConfig, "alias ll") {
		t.Fatalf("user config report should not render raw config content:\n%s", userConfig)
	}
	if strings.Contains(home, "color-scheme") {
		t.Fatalf("home module should not render raw dconf dump:\n%s", home)
	}
	desktop := readFile(t, out, "reports/desktop.md")
	for _, want := range []string{"Environment: gnome", "/home/alice/.local/share/fonts/demo.ttf", "/home/alice/.themes/demo", "/home/alice/.config/autostart/tool.desktop", "/home/alice/.config/Code/User/settings.json", "color-scheme='prefer-dark'"} {
		if !strings.Contains(desktop, want) {
			t.Fatalf("desktop report missing %q:\n%s", want, desktop)
		}
	}
	cfg = readFile(t, out, "hosts/generated/configuration.nix")
	if strings.Contains(cfg, "color-scheme") {
		t.Fatalf("configuration should not render raw dconf dump:\n%s", cfg)
	}
}

func TestProjectRendersOnlyConfirmedPackagesIntoNixSettings(t *testing.T) {
	out := t.TempDir()
	report := model.ScanReport{
		Host: model.Host{Hostname: "demo"},
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Decision: model.DecisionConfirmed},
			{Manager: "apt", Name: "git", NixNames: []string{"git"}, Decision: model.DecisionCandidate},
			{Manager: "apt", Name: "vim", NixNames: []string{"vim"}, Decision: model.DecisionExcluded},
			{Manager: "apt", Name: "unknown", Decision: model.DecisionCandidate},
		},
		Languages: model.Languages{
			NPM: []model.Package{
				{Manager: "npm", Name: "typescript", NixNames: []string{"nodePackages.typescript"}, Decision: model.DecisionConfirmed},
				{Manager: "npm", Name: "eslint", NixNames: []string{"nodePackages.eslint"}, Decision: model.DecisionCandidate},
			},
		},
		Containers: []model.Container{
			{Runtime: "docker", Name: "confirmed", Decision: model.DecisionConfirmed},
			{Runtime: "podman", Name: "candidate", Decision: model.DecisionCandidate},
		},
	}
	if err := Project(out, report); err != nil {
		t.Fatal(err)
	}
	cfg := readFile(t, out, "hosts/generated/configuration.nix")
	if !strings.Contains(cfg, "pkgs.curl") {
		t.Fatalf("confirmed package missing from systemPackages:\n%s", cfg)
	}
	if strings.Contains(cfg, "pkgs.git") || strings.Contains(cfg, "pkgs.vim") {
		t.Fatalf("candidate/excluded package leaked into systemPackages:\n%s", cfg)
	}
	home := readFile(t, out, "users/home.nix")
	if !strings.Contains(home, "pkgs.nodePackages.typescript") {
		t.Fatalf("confirmed npm package missing from home.packages:\n%s", home)
	}
	if strings.Contains(home, "nodePackages.eslint") {
		t.Fatalf("candidate npm package leaked into home.packages:\n%s", home)
	}
	containers := readFile(t, out, "modules/containers.nix")
	if !strings.Contains(containers, "virtualisation.docker.enable = true;") {
		t.Fatalf("confirmed docker runtime should be enabled:\n%s", containers)
	}
	if !strings.Contains(containers, "virtualisation.podman.enable = false;") {
		t.Fatalf("candidate podman runtime should not be enabled:\n%s", containers)
	}
	reportMD := readFile(t, out, "reports/migration-report.md")
	if !strings.Contains(reportMD, "`git` via apt -> `git` [candidate]") {
		t.Fatalf("candidate package missing from report:\n%s", reportMD)
	}
	if !strings.Contains(reportMD, "`unknown` via apt (no nix mapping) [candidate]") {
		t.Fatalf("unmapped package missing no mapping marker:\n%s", reportMD)
	}
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
