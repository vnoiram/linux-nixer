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
