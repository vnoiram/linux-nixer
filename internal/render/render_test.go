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
			Decision: model.DecisionCandidate,
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
			{Runtime: "podman", Name: "db", Image: "postgres:16", Decision: model.DecisionConfirmed},
		},
		Items: []model.Item{
			{Kind: "dev-project", Path: "/home/alice/app/pyproject.toml", Decision: model.DecisionCandidate, Reason: "project dependency or development environment file"},
			{Kind: "os-config", Path: "/etc/udev/rules.d/99-device.rules", Decision: model.DecisionCandidate},
			{Kind: "user-config", Path: "/home/alice/.gitconfig", Decision: model.DecisionCandidate},
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
	if strings.Contains(services, "excluded") {
		t.Fatalf("services module included excluded service:\n%s", services)
	}
	containers := readFile(t, out, "modules/containers.nix")
	if !strings.Contains(containers, "virtualisation.docker.enable = true;") {
		t.Fatalf("containers module should enable docker for compose:\n%s", containers)
	}
	if !strings.Contains(containers, "virtualisation.podman.enable = true;") {
		t.Fatalf("containers module should enable podman:\n%s", containers)
	}
	if !strings.Contains(containers, "/srv/app/compose.yml") || !strings.Contains(containers, "postgres:16") {
		t.Fatalf("containers module missing TODOs:\n%s", containers)
	}
	fs := readFile(t, out, "modules/filesystem-findings.nix")
	if !strings.Contains(fs, "/usr/local/bin/tool") {
		t.Fatalf("filesystem module missing script finding:\n%s", fs)
	}
	if strings.Contains(fs, "id_ed25519") || strings.Contains(fs, "/tmp/excluded") {
		t.Fatalf("filesystem module leaked secret/excluded finding:\n%s", fs)
	}
	dev := readFile(t, out, "reports/dev-projects.md")
	if !strings.Contains(dev, "/home/alice/app/pyproject.toml") {
		t.Fatalf("dev project report missing project:\n%s", dev)
	}
	home := readFile(t, out, "users/home.nix")
	if !strings.Contains(home, "/home/alice/.gitconfig") {
		t.Fatalf("home module missing user config TODO:\n%s", home)
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
