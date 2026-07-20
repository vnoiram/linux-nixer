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
		Users: []model.User{
			{Name: "root", UID: "0", GID: "0", Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}},
			{Name: "alice", UID: "1000", GID: "1000", Home: "/home/alice", Shell: "/bin/zsh", Groups: []string{"alice", "docker", "sudo", "video"}},
			{Name: "daemon", UID: "1", GID: "1", Home: "/usr/sbin", Shell: "/usr/sbin/nologin", Groups: []string{"daemon"}, System: true},
		},
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Version: "8.0", Source: "apt-mark:manual", NixNames: []string{"curl"}, Decision: model.DecisionCandidate},
			{Manager: "apt", Name: "excluded", Source: "apt-mark:manual", Decision: model.DecisionExcluded},
			{Manager: "snap", Name: "hello", Version: "1.0", Source: "/snap/hello", Decision: model.DecisionCandidate},
			{Manager: "flatpak", Name: "org.example.App", Source: "flathub", Decision: model.DecisionCandidate},
			{Manager: "appimage", Name: "Tool", Source: "/home/alice/Applications/Tool.AppImage", Decision: model.DecisionMigrationNote},
			{Manager: "homebrew", Name: "hello", Source: "/home/linuxbrew/.linuxbrew/Cellar/hello", Decision: model.DecisionCandidate},
		},
		Services: []model.Service{
			{
				Manager:          "systemd",
				Name:             "custom.service",
				Path:             "/etc/systemd/system/custom.service",
				Description:      "Custom app",
				User:             "app",
				WorkingDirectory: "/srv/app",
				ExecStart:        "/opt/vendor/bin/app --token=super-secret",
				EnvironmentFiles: []string{"/etc/default/custom"},
				WantedBy:         []string{"multi-user.target"},
				Decision:         model.DecisionCandidate,
			},
			{Manager: "systemd", Name: "custom.timer", Path: "/etc/systemd/system/custom.timer", Description: "Custom timer", Schedule: "OnCalendar=daily", Decision: model.DecisionCandidate},
			{Manager: "cron", Name: "job", Path: "/etc/cron.d/job", User: "root", ExecStart: "/usr/local/bin/job", Schedule: "15 2 * * *", Decision: model.DecisionCandidate},
			{Manager: "cron", Name: "excluded", Path: "/etc/cron.d/excluded", Decision: model.DecisionExcluded},
		},
		Containers: []model.Container{
			{Runtime: "compose", Compose: "/srv/app/compose.yml", Decision: model.DecisionCandidate},
			{Runtime: "podman", Name: "db", Image: "postgres:16", Digest: "postgres@sha256:demo", Ports: []string{"127.0.0.1:5432->5432/tcp"}, Mounts: []string{"volume:pgdata:/var/lib/postgresql/data"}, Env: map[string]string{"POSTGRES_PASSWORD": ""}, Decision: model.DecisionConfirmed},
			{Runtime: "docker", Name: "excluded", Image: "redis:7", Env: map[string]string{"REDIS_PASSWORD": "secret"}, Decision: model.DecisionExcluded},
		},
		GitSources: []model.GitSource{
			{Path: "/home/alice/app", Remote: "https://example.com/app.git", Commit: "abc123", Dirty: true, Build: []string{"branch:main", "submodules", "flake.nix"}, Decision: model.DecisionCandidate},
			{Path: "/opt/excluded", Remote: "https://example.com/excluded.git", Commit: "def456", Decision: model.DecisionExcluded},
		},
		Languages: model.Languages{
			NPM: []model.Package{
				{Manager: "pnpm", Name: "prettier", Version: "3.0.0", Source: "/home/alice/.local/share/pnpm/global/5/node_modules/prettier/package.json", NixNames: []string{"nodePackages.prettier"}, Decision: model.DecisionCandidate},
				{Manager: "npm", Name: "excluded", Decision: model.DecisionExcluded},
			},
			Python: []model.PythonEnv{
				{Path: "/home/alice/.local/pipx/venvs/ruff", Kind: "pipx", Packages: []model.Package{{Manager: "pipx", Name: "ruff", NixNames: []string{"ruff"}, Decision: model.DecisionCandidate}}},
				{Path: "/home/alice/app/.venv", Kind: "venv"},
			},
			Conda: []model.Package{
				{Manager: "conda", Name: "data", Source: "/home/alice/miniconda3/envs/data", Decision: model.DecisionMigrationNote},
			},
			Cargo: []model.Package{{Manager: "cargo", Name: "starship", Source: "/home/alice/.cargo/bin/starship", NixNames: []string{"starship"}, Decision: model.DecisionCandidate}},
			Go:    []model.Package{{Manager: "go-install", Name: "gopls", Source: "/home/alice/go/bin/gopls", NixNames: []string{"gopls"}, Decision: model.DecisionCandidate}},
			Gem:   []model.Package{{Manager: "gem", Name: "bundler", Source: "/home/alice/.gem/ruby/3.3.0/bin/bundler", NixNames: []string{"bundler"}, Decision: model.DecisionCandidate}},
			VMs:   []model.VersionTool{{Name: "mise", Path: "/home/alice/.local/share/mise"}, {Name: ".tool-versions", Path: "/home/alice/.tool-versions"}},
		},
		Items: []model.Item{
			{Kind: "apt-source", Name: "sources.list", Path: "/etc/apt/sources.list", Source: "deb http://archive.ubuntu.com/ubuntu noble main", Decision: model.DecisionCandidate, Reason: "apt repository source"},
			{Kind: "apt-keyring", Name: "vendor.gpg", Path: "/etc/apt/keyrings/vendor.gpg", Decision: model.DecisionCandidate, Reason: "apt repository trust keyring"},
			{Kind: "apt-preference", Name: "pin", Path: "/etc/apt/preferences.d/pin", Decision: model.DecisionCandidate, Reason: "apt package pinning or repository priority"},
			{Kind: "apt-config", Name: "99local", Path: "/etc/apt/apt.conf.d/99local", Decision: model.DecisionCandidate, Reason: "apt client configuration"},
			{Kind: "apt-source", Name: "excluded", Path: "/etc/apt/sources.list.d/excluded.list", Decision: model.DecisionExcluded, Reason: "apt repository source"},
			{Kind: "dev-project", Path: "/home/alice/app/pyproject.toml", Decision: model.DecisionCandidate, Reason: "project dependency or development environment file"},
			{Kind: "language-project", Name: "package.json", Path: "/home/alice/app/package.json", Decision: model.DecisionCandidate, Reason: "node dependency or package manager file"},
			{Kind: "language-project", Name: "pyproject.toml", Path: "/home/alice/app/pyproject.toml", Decision: model.DecisionCandidate, Reason: "python dependency or virtual environment file"},
			{Kind: "language-project", Name: "excluded", Path: "/home/alice/app/excluded.lock", Decision: model.DecisionExcluded, Reason: "excluded language file"},
			{Kind: "os-config", Name: "99-device.rules", Path: "/etc/udev/rules.d/99-device.rules", Decision: model.DecisionCandidate, Reason: "kernel or device tuning"},
			{Kind: "os-config", Name: "home.nmconnection", Path: "/etc/NetworkManager/system-connections/home.nmconnection", Decision: model.DecisionMigrationNote, Reason: "network connection profile may contain credentials", Details: map[string]string{"id": "home", "type": "wifi", "interface-name": "wlp1s0"}},
			{Kind: "os-config", Name: "sudoers", Path: "/etc/sudoers", Decision: model.DecisionCandidate, Reason: "auth and security configuration", Details: map[string]string{"group-rules": "1", "nopasswd-rules": "1"}},
			{Kind: "os-config", Name: "sshd", Path: "/etc/pam.d/sshd", Decision: model.DecisionCandidate, Reason: "auth and security configuration", Details: map[string]string{"important-modules": "pam_faillock.so,pam_u2f.so", "rules": "2"}},
			{Kind: "os-config", Name: "wg0.conf", Path: "/etc/wireguard/wg0.conf", Decision: model.DecisionCandidate, Reason: "network configuration", Details: map[string]string{"peers": "1", "secret-refs": "2", "dns": "present"}},
			{Kind: "os-config", Name: "client.conf", Path: "/etc/openvpn/client.conf", Decision: model.DecisionCandidate, Reason: "network configuration", Details: map[string]string{"remotes": "1", "routes": "1", "secret-refs": "1"}},
			{Kind: "os-config", Name: "app", Path: "/etc/nginx/sites-enabled/app", Decision: model.DecisionCandidate, Reason: "web server configuration"},
			{Kind: "os-config", Name: "ufw.conf", Path: "/etc/ufw/ufw.conf", Decision: model.DecisionExcluded, Reason: "firewall configuration"},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.kube/config", Decision: model.DecisionMigrationNote, Reason: "kubernetes configuration may contain credentials", Details: map[string]string{"contexts": "1", "clusters": "1", "users": "1", "current-context": "present", "secret-refs": "1"}},
			{Kind: "devops-config", Name: "config.json", Path: "/home/alice/.docker/config.json", Decision: model.DecisionMigrationNote, Reason: "docker client configuration may contain credentials", Details: map[string]string{"registries": "1", "credential-store": "present", "credential-helpers": "1", "secret-refs": "1"}},
			{Kind: "devops-config", Name: "repositories.yaml", Path: "/home/alice/.config/helm/repositories.yaml", Decision: model.DecisionMigrationNote, Reason: "helm repository configuration may contain credentials", Details: map[string]string{"repositories": "2", "repository-schemes": "https,oci", "secret-refs": "1"}},
			{Kind: "devops-config", Name: ".terraformrc", Path: "/home/alice/.terraformrc", Decision: model.DecisionMigrationNote, Reason: "terraform CLI configuration may contain credentials", Details: map[string]string{"credential-hosts": "1", "credential-helper": "present", "plugin-cache": "present", "secret-refs": "1"}},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.aws/config", Decision: model.DecisionCandidate, Reason: "aws CLI configuration", Details: map[string]string{"profiles": "2", "regions": "2", "sso-settings": "2"}},
			{Kind: "devops-config", Name: "config_default", Path: "/home/alice/.config/gcloud/configurations/config_default", Decision: model.DecisionMigrationNote, Reason: "gcloud configuration may contain credentials", Details: map[string]string{"sections": "2", "properties": "3", "project": "present", "account": "present"}},
			{Kind: "devops-config", Name: "config", Path: "/home/alice/.azure/config", Decision: model.DecisionMigrationNote, Reason: "azure CLI configuration may contain credentials", Details: map[string]string{"sections": "2", "settings": "3", "cloud": "present", "subscription": "present", "tenant": "present"}},
			{Kind: "devops-config", Name: "excluded", Path: "/home/alice/.kube/excluded", Decision: model.DecisionExcluded, Reason: "kubernetes configuration may contain credentials"},
			{Kind: "cicd-config", Name: "ci.yml", Path: "/home/alice/app/.github/workflows/ci.yml", Decision: model.DecisionCandidate, Reason: "github actions workflow", Details: map[string]string{"jobs": "1", "secret-refs": "1", "triggers": "push,workflow_dispatch"}},
			{Kind: "cicd-config", Name: "deploy-prod.sh", Path: "/srv/app/scripts/deploy-prod.sh", Decision: model.DecisionCandidate, Reason: "deploy or release script", Details: map[string]string{"shebang": "/bin/sh", "targets": "deploy,release"}},
			{Kind: "backup-config", Name: "rclone", Path: "/home/alice/.config/rclone/rclone.conf", Decision: model.DecisionMigrationNote, Reason: "rclone backup or sync configuration", Details: map[string]string{"tool": "rclone", "remote-types": "s3", "secret-refs": "2"}},
			{Kind: "backup-config", Name: "restic", Path: "/etc/systemd/system/restic-backup.service", Decision: model.DecisionMigrationNote, Reason: "backup or sync job", Details: map[string]string{"tools": "restic", "schedule": "OnCalendar=daily"}},
			{Kind: "user-config", Path: "/home/alice/.gitconfig", Decision: model.DecisionCandidate},
			{Kind: "user-config", Name: "ssh/config", Path: "/home/alice/.ssh/config", Decision: model.DecisionCandidate, Reason: "user tool configuration", Details: map[string]string{"hosts": "2", "identity-files": "1", "markers": "proxyjump,user"}},
			{Kind: "user-config", Name: "authorized_keys", Path: "/home/alice/.ssh/authorized_keys", Decision: model.DecisionCandidate, Reason: "user tool configuration", Details: map[string]string{"keys": "2", "restricted-keys": "1", "key-types": "ssh-ed25519,ssh-rsa"}},
			{Kind: "credential-store", Name: ".password-store", Path: "/home/alice/.password-store", Decision: model.DecisionMigrationNote, Reason: "credential or key store marker; migrate manually", Details: map[string]string{"store": "password-store"}},
			{Kind: "shell-config", Name: ".zshrc", Path: "/home/alice/.zshrc", Decision: model.DecisionCandidate, Reason: "shell or login environment configuration"},
			{Kind: "shell-plugin", Name: ".oh-my-zsh", Path: "/home/alice/.oh-my-zsh", Decision: model.DecisionCandidate, Reason: "shell plugin manager or plugin tree"},
			{Kind: "user-bin", Name: "tool", Path: "/home/alice/.local/bin/tool", Decision: model.DecisionCandidate, Reason: "user-local executable"},
			{Kind: "direnv", Name: ".envrc", Path: "/home/alice/app/.envrc", Decision: model.DecisionCandidate, Reason: "direnv project environment file"},
			{Kind: "desktop-config", Name: "settings.json", Path: "/home/alice/.config/Code/User/settings.json", Decision: model.DecisionCandidate, Reason: "desktop environment configuration"},
			{Kind: "browser-profile", Name: "alice.default-release", Path: "/home/alice/.mozilla/firefox/alice.default-release", Decision: model.DecisionMigrationNote, Reason: "browser profile may contain cookies, history, saved sessions, and credentials"},
			{Kind: "browser-extension", Name: "addon@example.xpi", Path: "/home/alice/.mozilla/firefox/alice.default-release/extensions/addon@example.xpi", Decision: model.DecisionMigrationNote, Reason: "browser extension marker; review sync/export strategy manually"},
			{Kind: "editor-profile", Name: "publisher.tool-1.0.0", Path: "/home/alice/.vscode/extensions/publisher.tool-1.0.0", Decision: model.DecisionCandidate, Reason: "editor settings, extensions, or IDE profile"},
			{Kind: "hardware-config", Name: "cups", Path: "/etc/cups/printers.conf", Decision: model.DecisionMigrationNote, Reason: "printer configuration", Details: map[string]string{"category": "printer", "tool": "cups", "printers": "1", "device-uri-schemes": "ipp"}},
			{Kind: "hardware-config", Name: "bluetooth", Path: "/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info", Decision: model.DecisionMigrationNote, Reason: "bluetooth controller or paired device marker", Details: map[string]string{"category": "bluetooth", "tool": "bluez", "paired-device": "present", "paired": "true"}},
			{Kind: "hardware-config", Name: "sane", Path: "/etc/sane.d/dll.conf", Decision: model.DecisionMigrationNote, Reason: "scanner backend configuration", Details: map[string]string{"category": "scanner", "tool": "sane", "enabled-backends": "2", "network-backend": "present"}},
			{Kind: "hardware-config", Name: "pipewire", Path: "/etc/pipewire/pipewire.conf", Decision: model.DecisionMigrationNote, Reason: "audio profile or server configuration", Details: map[string]string{"category": "audio", "tool": "pipewire", "settings": "1"}},
			{Kind: "hardware-config", Name: "u2f", Path: "/etc/u2f_mappings", Decision: model.DecisionMigrationNote, Reason: "security device or biometric configuration", Details: map[string]string{"category": "security-device", "tool": "u2f", "mappings": "1", "manual-enrollment": "recommended"}},
			{Kind: "hardware-config", Name: "tlp", Path: "/etc/tlp.conf", Decision: model.DecisionMigrationNote, Reason: "power management or firmware configuration", Details: map[string]string{"category": "power-firmware", "tool": "tlp", "settings": "1"}},
			{Kind: "hardware-config", Name: "keyd", Path: "/etc/keyd/default.conf", Decision: model.DecisionMigrationNote, Reason: "input device remapping or peripheral configuration", Details: map[string]string{"category": "input-device", "tool": "keyd", "sections": "2", "settings": "1"}},
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
			{Path: "/opt/vendor/bin/app", Type: "elf", Mode: "-rwxr-xr-x", Size: 7, SHA256: "abc123", Category: "executable", Reason: "ELF executable outside explicit package mapping; under /opt, commonly used for manually installed vendor applications", Decision: model.DecisionCandidate},
			{Path: "/usr/local/bin/tool", Type: "script", Mode: "-rwxr-xr-x", Size: 20, SHA256: "def456", Category: "script", Reason: "shebang script; under /usr/local executable path, commonly outside apt package ownership", Decision: model.DecisionCandidate},
			{Path: "/srv/app/app.service", Type: "systemd-unit", Mode: "-rw-r--r--", Size: 40, Category: "service", Reason: "systemd unit outside explicit package mapping; under /srv, commonly service or application data", Decision: model.DecisionCandidate},
			{Path: "/home/alice/.config/tool/config.toml", Type: "file", Mode: "-rw-r--r--", Size: 14, Category: "config", Reason: "configuration file outside explicit package mapping; under a user home directory", Decision: model.DecisionCandidate},
			{Path: "/home/alice/.ssh/id_ed25519", Type: "file", Mode: "-rw-------", Size: 32, SHA256: "secretsha", Category: "secret", Reason: "secret-like file excluded from generated Nix; under a user home directory", SecretRisk: true, Decision: model.DecisionMigrationNote},
			{Path: "/tmp/excluded", Category: "script", Decision: model.DecisionExcluded},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql", Type: "directory", Mode: "drwx------", Category: "stateful-data", Reason: "postgresql data directory", Decision: model.DecisionMigrationNote},
			{Path: "/var/lib/redis", Type: "directory", Mode: "drwxr-x---", Category: "stateful-data", Reason: "redis data directory", Decision: model.DecisionMigrationNote},
			{Path: "/var/lib/mysql/excluded", Category: "stateful-data", Decision: model.DecisionExcluded},
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
	for _, want := range []string{"Kernel and devices", "/etc/udev/rules.d/99-device.rules", "Network", "/etc/NetworkManager/system-connections/home.nmconnection", "id `home`", "interface-name `wlp1s0`", "type `wifi`", "/etc/wireguard/wg0.conf", "dns `present`", "/etc/openvpn/client.conf", "remotes `1`", "Auth and security", "/etc/sudoers", "nopasswd-rules `1`", "/etc/pam.d/sshd", "important-modules `pam_faillock.so,pam_u2f.so`", "Web servers", "/etc/nginx/sites-enabled/app", "Services", "custom.service", "Custom app", "user `app`", "working directory `/srv/app`", "exec `/opt/vendor/bin/app --token=<redacted>`", "environment files `/etc/default/custom`", "wanted by `multi-user.target`", "custom.timer", "schedule `OnCalendar=daily`", "job", "schedule `15 2 * * *`"} {
		if !strings.Contains(systemConfig, want) {
			t.Fatalf("system config report missing %q:\n%s", want, systemConfig)
		}
	}
	if strings.Contains(systemConfig, "excluded") || strings.Contains(systemConfig, "ufw.conf") || strings.Contains(systemConfig, "super-secret") {
		t.Fatalf("system config report included excluded entries or raw secret:\n%s", systemConfig)
	}
	devopsConfig := readFile(t, out, "reports/devops-config.md")
	for _, want := range []string{"Kubernetes", "/home/alice/.kube/config", "contexts `1`", "current-context `present`", "Docker", "/home/alice/.docker/config.json", "credential-store `present`", "registries `1`", "Helm", "/home/alice/.config/helm/repositories.yaml", "repositories `2`", "repository-schemes `https,oci`", "Terraform", "/home/alice/.terraformrc", "credential-hosts `1`", "plugin-cache `present`", "AWS", "/home/alice/.aws/config", "profiles `2`", "regions `2`", "GCP", "/home/alice/.config/gcloud/configurations/config_default", "project `present`", "Azure", "/home/alice/.azure/config", "subscription `present`", "CI/CD", "/home/alice/app/.github/workflows/ci.yml", "triggers `push,workflow_dispatch`", "/srv/app/scripts/deploy-prod.sh", "targets `deploy,release`"} {
		if !strings.Contains(devopsConfig, want) {
			t.Fatalf("devops config report missing %q:\n%s", want, devopsConfig)
		}
	}
	if strings.Contains(devopsConfig, "super-secret") || strings.Contains(devopsConfig, "excluded") || strings.Contains(devopsConfig, "secret-project") {
		t.Fatalf("devops config report leaked raw secret or excluded entry:\n%s", devopsConfig)
	}
	backupSync := readFile(t, out, "reports/backup-sync.md")
	for _, want := range []string{"# Backup and sync findings", "Rclone", "/home/alice/.config/rclone/rclone.conf", "remote-types `s3`", "secret-refs `2`", "Restic", "/etc/systemd/system/restic-backup.service", "schedule `OnCalendar=daily`"} {
		if !strings.Contains(backupSync, want) {
			t.Fatalf("backup sync report missing %q:\n%s", want, backupSync)
		}
	}
	if strings.Contains(backupSync, "super-secret") || strings.Contains(backupSync, "raw-secret") {
		t.Fatalf("backup sync report leaked raw secret:\n%s", backupSync)
	}
	hardware := readFile(t, out, "reports/hardware.md")
	for _, want := range []string{"# Hardware and peripheral findings", "Printers", "/etc/cups/printers.conf", "device-uri-schemes `ipp`", "Bluetooth", "/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info", "paired-device `present`", "Scanners", "/etc/sane.d/dll.conf", "enabled-backends `2`", "Audio", "/etc/pipewire/pipewire.conf", "Security devices", "/etc/u2f_mappings", "manual-enrollment `recommended`", "Power and firmware", "/etc/tlp.conf", "Input devices", "/etc/keyd/default.conf"} {
		if !strings.Contains(hardware, want) {
			t.Fatalf("hardware report missing %q:\n%s", want, hardware)
		}
	}
	for _, unwanted := range []string{"user:secret", "raw-pairing-secret", "secret-u2f-mapping"} {
		if strings.Contains(hardware, unwanted) {
			t.Fatalf("hardware report leaked raw detail %q:\n%s", unwanted, hardware)
		}
	}
	usersReport := readFile(t, out, "reports/users.md")
	for _, want := range []string{"# User account findings", "Primary Home Manager user: `alice`", "Human users", "`alice` uid `1000`", "groups `alice, docker, sudo, video`", "Privileged and group-sensitive users", "System users", "`daemon` uid `1`", "`root` uid `0`"} {
		if !strings.Contains(usersReport, want) {
			t.Fatalf("users report missing %q:\n%s", want, usersReport)
		}
	}
	packageSources := readFile(t, out, "reports/package-sources.md")
	for _, want := range []string{"# Package source findings", "Apt packages", "`curl` via apt -> `curl` [candidate] version `8.0` source `apt-mark:manual`", "Apt repositories", "/etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu noble main", "Apt keyrings", "/etc/apt/keyrings/vendor.gpg", "Apt preferences", "/etc/apt/preferences.d/pin", "Apt configuration", "/etc/apt/apt.conf.d/99local", "Alternative package ecosystems", "`hello` via snap", "`org.example.App` via flatpak", "`Tool` via appimage", "`hello` via homebrew"} {
		if !strings.Contains(packageSources, want) {
			t.Fatalf("package sources report missing %q:\n%s", want, packageSources)
		}
	}
	if strings.Contains(packageSources, "excluded") {
		t.Fatalf("package sources report included excluded entry:\n%s", packageSources)
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
	gitSources := readFile(t, out, "reports/git-sources.md")
	for _, want := range []string{"# Git source findings", "/home/alice/app", "https://example.com/app.git", "abc123", "dirty: true", "branch:main, submodules, flake.nix"} {
		if !strings.Contains(gitSources, want) {
			t.Fatalf("git sources report missing %q:\n%s", want, gitSources)
		}
	}
	if strings.Contains(gitSources, "/opt/excluded") {
		t.Fatalf("git sources report included excluded source:\n%s", gitSources)
	}
	languages := readFile(t, out, "reports/languages.md")
	for _, want := range []string{"# Language ecosystem findings", "Node global packages", "`prettier` via pnpm", "Python environments", "/home/alice/.local/pipx/venvs/ruff", "`ruff` via pipx", "Conda environments", "`data` via conda", "Cargo-installed binaries", "`starship` via cargo", "Go-installed binaries", "`gopls` via go-install", "Ruby gems", "`bundler` via gem", "Version managers", "mise", ".tool-versions", "Project language files", "/home/alice/app/package.json", "/home/alice/app/pyproject.toml"} {
		if !strings.Contains(languages, want) {
			t.Fatalf("languages report missing %q:\n%s", want, languages)
		}
	}
	if strings.Contains(languages, "excluded") {
		t.Fatalf("languages report included excluded entry:\n%s", languages)
	}
	fs := readFile(t, out, "modules/filesystem-findings.nix")
	if !strings.Contains(fs, "/usr/local/bin/tool") {
		t.Fatalf("filesystem module missing script finding:\n%s", fs)
	}
	if strings.Contains(fs, "id_ed25519") || strings.Contains(fs, "/tmp/excluded") {
		t.Fatalf("filesystem module leaked secret/excluded finding:\n%s", fs)
	}
	filesystemReport := readFile(t, out, "reports/filesystem.md")
	for _, want := range []string{"# Filesystem migration findings", "Executable files", "/opt/vendor/bin/app", "sha256 `abc123`", "Scripts", "/usr/local/bin/tool", "Service and desktop entries", "/srv/app/app.service", "Config files", "/home/alice/.config/tool/config.toml", "Secret-risk files", "/home/alice/.ssh/id_ed25519", "secret-risk", "Stateful data", "/var/lib/postgresql", "postgresql data directory", "/var/lib/redis", "redis data directory"} {
		if !strings.Contains(filesystemReport, want) {
			t.Fatalf("filesystem report missing %q:\n%s", want, filesystemReport)
		}
	}
	if strings.Contains(filesystemReport, "/tmp/excluded") || strings.Contains(filesystemReport, "/var/lib/mysql/excluded") || strings.Contains(filesystemReport, "PRIVATE KEY") {
		t.Fatalf("filesystem report included excluded finding or raw secret content:\n%s", filesystemReport)
	}
	checklist := readFile(t, out, "reports/migration-checklist.md")
	for _, want := range []string{
		"# Manual migration checklist",
		"## Before applying Nix",
		"Confirm whether `curl` via apt should be promoted to `confirmed`",
		"Find or package a Nix equivalent for `hello` via snap",
		"Recreate apt repository `/etc/apt/sources.list`",
		"Confirm `prettier` from pnpm as a Home Manager package",
		"Translate systemd service `custom.service`",
		"exec `/opt/vendor/bin/app --token=<redacted>`",
		"user `app`",
		"schedule `15 2 * * *`",
		"Translate system configuration `/etc/NetworkManager/system-connections/home.nmconnection`",
		"Review id `home`, interface-name `wlp1s0`, type `wifi`",
		"Translate system configuration `/etc/wireguard/wg0.conf`",
		"Review dns `present`, peers `1`, secret-refs `2`",
		"Translate system configuration `/etc/sudoers`",
		"Review group-rules `1`, nopasswd-rules `1`",
		"Translate compose `/srv/app/compose.yml`",
		"Review CI/CD configuration `/home/alice/app/.github/workflows/ci.yml`",
		"Review jobs `1`, secret-refs `1`, triggers `push,workflow_dispatch`",
		"Review DevOps provider configuration `/home/alice/.kube/config`",
		"Review clusters `1`, contexts `1`, current-context `present`, secret-refs `1`",
		"Review DevOps provider configuration `/home/alice/.docker/config.json`",
		"Review credential-helpers `1`, credential-store `present`, registries `1`, secret-refs `1`",
		"backup dirty changes before migration",
		"Decide how to recreate `/usr/local/bin/tool`",
		"Back up and restore secret-risk file `/home/alice/.ssh/id_ed25519` manually",
		"Back up stateful data `/var/lib/postgresql` (postgresql data directory)",
		"Back up stateful data `/var/lib/redis` (redis data directory)",
		"Review backup/sync configuration `/home/alice/.config/rclone/rclone.conf`",
		"Review remote-types `s3`, secret-refs `2`, tool `rclone`",
		"Confirm user `alice` home `/home/alice`",
		"Migrate credential store `/home/alice/.password-store` manually",
		"Review store `password-store`",
		"Back up or sync browser profile `/home/alice/.mozilla/firefox/alice.default-release` manually",
		"Review browser extension marker `/home/alice/.mozilla/firefox/alice.default-release/extensions/addon@example.xpi`",
		"Review editor profile `/home/alice/.vscode/extensions/publisher.tool-1.0.0`",
		"Review hardware/peripheral configuration `/etc/cups/printers.conf`",
		"Review category `printer`, device-uri-schemes `ipp`, printers `1`, tool `cups`",
		"Review hardware/peripheral configuration `/etc/u2f_mappings`",
		"Review category `security-device`, manual-enrollment `recommended`, mappings `1`, tool `u2f`",
	} {
		if !strings.Contains(checklist, want) {
			t.Fatalf("migration checklist missing %q:\n%s", want, checklist)
		}
	}
	for _, unwanted := range []string{"`excluded`", "/tmp/excluded", "redis:7", "PRIVATE KEY", "super-secret", "raw-cookie-secret", "raw-history", "psk", "hidden", "raw-secret"} {
		if strings.Contains(checklist, unwanted) {
			t.Fatalf("migration checklist included unwanted %q:\n%s", unwanted, checklist)
		}
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
	for _, want := range []string{"Shell configuration", "/home/alice/.zshrc", "Shell plugins", "/home/alice/.oh-my-zsh", "User-local executables", "/home/alice/.local/bin/tool", "User tool configuration", "/home/alice/.gitconfig", "/home/alice/.ssh/config", "identity-files `1`", "/home/alice/.ssh/authorized_keys", "restricted-keys `1`", "Credential stores", "/home/alice/.password-store", "store `password-store`", "Direnv", "/home/alice/app/.envrc"} {
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
	if strings.Contains(home, ".mozilla/firefox") || strings.Contains(home, ".vscode/extensions") {
		t.Fatalf("home module should not render GUI profile paths:\n%s", home)
	}
	desktop := readFile(t, out, "reports/desktop.md")
	for _, want := range []string{"Environment: gnome", "/home/alice/.local/share/fonts/demo.ttf", "/home/alice/.themes/demo", "/home/alice/.config/autostart/tool.desktop", "/home/alice/.config/Code/User/settings.json", "Browser profiles", "/home/alice/.mozilla/firefox/alice.default-release", "Browser extensions", "addon@example.xpi", "Editor profiles", "/home/alice/.vscode/extensions/publisher.tool-1.0.0", "color-scheme='prefer-dark'"} {
		if !strings.Contains(desktop, want) {
			t.Fatalf("desktop report missing %q:\n%s", want, desktop)
		}
	}
	for _, unwanted := range []string{"raw-cookie-secret", "raw-history"} {
		if strings.Contains(desktop, unwanted) {
			t.Fatalf("desktop report leaked profile content %q:\n%s", unwanted, desktop)
		}
	}
	cfg = readFile(t, out, "hosts/generated/configuration.nix")
	if strings.Contains(cfg, "color-scheme") || strings.Contains(cfg, ".mozilla/firefox") || strings.Contains(cfg, ".vscode/extensions") {
		t.Fatalf("configuration should not render raw desktop/profile details:\n%s", cfg)
	}
	reportMD := readFile(t, out, "reports/migration-report.md")
	if !strings.Contains(reportMD, "## Users") || !strings.Contains(reportMD, "Primary Home Manager user: `alice`") || !strings.Contains(reportMD, "Privileged or group-sensitive user: `alice` groups `alice, docker, sudo, video`") {
		t.Fatalf("migration report missing user account section:\n%s", reportMD)
	}
	if !strings.Contains(reportMD, "## Git sources") || !strings.Contains(reportMD, "/home/alice/app") {
		t.Fatalf("migration report missing git source section:\n%s", reportMD)
	}
	if !strings.Contains(reportMD, "`curl` via apt -> `curl` [candidate] source `apt-mark:manual`") || !strings.Contains(reportMD, "/etc/apt/sources.list") {
		t.Fatalf("migration report missing package source hints:\n%s", reportMD)
	}
	if !strings.Contains(reportMD, "## Language packages") || !strings.Contains(reportMD, "`prettier` via pnpm") || !strings.Contains(reportMD, "version manager `mise`") || !strings.Contains(reportMD, "/home/alice/app/package.json") {
		t.Fatalf("migration report missing language section:\n%s", reportMD)
	}
	if !strings.Contains(reportMD, "/opt/vendor/bin/app") || !strings.Contains(reportMD, "sha256 `abc123`") || !strings.Contains(reportMD, "/var/lib/postgresql") || !strings.Contains(reportMD, "postgresql data directory") {
		t.Fatalf("migration report missing filesystem metadata:\n%s", reportMD)
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

func TestProjectRendersConservativeNixOptions(t *testing.T) {
	out := t.TempDir()
	report := model.ScanReport{
		Host: model.Host{Hostname: "demo"},
		Users: []model.User{
			{Name: "root", UID: "0", GID: "0", Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}},
			{Name: "alice", UID: "1000", GID: "1000", Home: "/home/alice", Shell: "/bin/zsh", Groups: []string{"alice", "docker", "sudo", "video"}},
			{Name: "daemon", UID: "1", GID: "1", Home: "/usr/sbin", Shell: "/usr/sbin/nologin", Groups: []string{"daemon"}, System: true},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "custom.service", Path: "/etc/systemd/system/custom.service", Decision: model.DecisionConfirmed},
			{Manager: "systemd", Name: "candidate.service", Path: "/etc/systemd/system/candidate.service", Decision: model.DecisionCandidate},
		},
		Items: []model.Item{
			{Kind: "shell-config", Name: ".zshrc", Path: "/home/alice/.zshrc", Decision: model.DecisionConfirmed, Reason: "shell or login environment configuration"},
			{Kind: "user-config", Name: ".gitconfig", Path: "/home/alice/.gitconfig", Decision: model.DecisionConfirmed, Reason: "user tool configuration"},
			{Kind: "user-config", Name: ".tmux.conf", Path: "/home/alice/.tmux.conf", Decision: model.DecisionConfirmed, Reason: "user tool configuration"},
			{Kind: "user-config", Name: "starship.toml", Path: "/home/alice/.config/starship.toml", Decision: model.DecisionConfirmed, Reason: "user tool configuration"},
			{Kind: "shell-config", Name: ".bashrc", Path: "/home/alice/.bashrc", Decision: model.DecisionCandidate, Reason: "candidate shell config"},
			{Kind: "user-config", Name: ".gitconfig", Path: "/home/bob/.gitconfig", Decision: model.DecisionConfirmed, Reason: "other user config"},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true, Decision: model.DecisionMigrationNote},
		},
	}
	if err := Project(out, report); err != nil {
		t.Fatal(err)
	}

	cfg := readFile(t, out, "hosts/generated/configuration.nix")
	for _, want := range []string{
		`programs.zsh.enable = true;`,
		`users.users."alice" = {`,
		`isNormalUser = true;`,
		`home = "/home/alice";`,
		`"docker"`,
		`"sudo"`,
		`"video"`,
		`shell = pkgs.zsh;`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("configuration missing %q:\n%s", want, cfg)
		}
	}
	for _, notWant := range []string{`users.users."root"`, `users.users."daemon"`} {
		if strings.Contains(cfg, notWant) {
			t.Fatalf("configuration should not contain %q:\n%s", notWant, cfg)
		}
	}

	home := readFile(t, out, "users/home.nix")
	for _, want := range []string{`programs.zsh.enable = true;`, `programs.git.enable = true;`, `programs.tmux.enable = true;`, `programs.starship.enable = true;`} {
		if !strings.Contains(home, want) {
			t.Fatalf("home missing %q:\n%s", want, home)
		}
	}
	for _, notWant := range []string{`programs.bash.enable = true;`, `PRIVATE KEY`, `programs.fish.enable = true;`} {
		if strings.Contains(home, notWant) {
			t.Fatalf("home should not contain %q:\n%s", notWant, home)
		}
	}

	services := readFile(t, out, "modules/services.nix")
	if !strings.Contains(services, `systemd.services."custom".enable = true;`) {
		t.Fatalf("services missing generated systemd hint:\n%s", services)
	}
	if strings.Contains(services, `systemd.services."candidate".enable = true;`) {
		t.Fatalf("services should not generate candidate systemd hint:\n%s", services)
	}

	reportMD := readFile(t, out, "reports/migration-report.md")
	for _, want := range []string{"## Generated Nix summary", "user option: `users.users.alice`", "host shell option: `programs.zsh.enable`", "Home Manager option: `programs.git.enable`", "service hint: `systemd.services.custom.enable`"} {
		if !strings.Contains(reportMD, want) {
			t.Fatalf("migration report missing generated Nix summary %q:\n%s", want, reportMD)
		}
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
