package review

import (
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestApplyConfirmsSafeMappedPackages(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
			{Manager: "apt", Name: "unknown"},
		},
	}
	got := Apply(report, Options{AutoSafe: true})
	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("mapped package decision=%q", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("unknown package decision=%q", got.Packages[1].Decision)
	}
}

func TestApplyExcludesPathPrefixAndKeepsSecretsAsMigrationNotes(t *testing.T) {
	report := model.ScanReport{
		FilesystemDiff: []model.FileFinding{
			{Path: "/tmp/tool", Category: "script"},
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true},
		},
	}
	got := Apply(report, Options{ExcludePathPrefixes: []string{"/tmp"}})
	if got.FilesystemDiff[0].Decision != model.DecisionExcluded {
		t.Fatalf("excluded path decision=%q", got.FilesystemDiff[0].Decision)
	}
	if got.FilesystemDiff[1].Decision != model.DecisionMigrationNote {
		t.Fatalf("secret decision=%q", got.FilesystemDiff[1].Decision)
	}
}
