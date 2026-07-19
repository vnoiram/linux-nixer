package review

import (
	"bytes"
	"strings"
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

func TestInteractiveAppliesChoices(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl"},
			{Manager: "apt", Name: "git"},
			{Manager: "apt", Name: "vim"},
			{Manager: "apt", Name: "tmux"},
			{Manager: "apt", Name: "jq"},
		},
	}
	in := strings.NewReader("c\nx\nt\nm\ns\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	wants := []model.Decision{
		model.DecisionConfirmed,
		model.DecisionExcluded,
		model.DecisionTODO,
		model.DecisionMigrationNote,
		model.DecisionCandidate,
	}
	for i, want := range wants {
		if got.Packages[i].Decision != want {
			t.Fatalf("package %d decision=%q, want %q", i, got.Packages[i].Decision, want)
		}
	}
	if !strings.Contains(out.String(), "choose c=confirmed") {
		t.Fatalf("interactive prompt missing choices: %s", out.String())
	}
}

func TestInteractiveProtectsSecretAndStatefulData(t *testing.T) {
	report := model.ScanReport{
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Category: "stateful-data"},
		},
	}
	in := strings.NewReader("c\nc\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	if got.FilesystemDiff[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("secret decision=%q, want migration-note", got.FilesystemDiff[0].Decision)
	}
	if got.StatefulData[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("stateful decision=%q, want migration-note", got.StatefulData[0].Decision)
	}
	if strings.Count(out.String(), "protected finding cannot be confirmed") != 2 {
		t.Fatalf("expected protected warning twice, got: %s", out.String())
	}
}

func TestInteractiveQuitKeepsRemainingDecisions(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl"},
			{Manager: "apt", Name: "git"},
		},
	}
	in := strings.NewReader("q\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	if got.Packages[0].Decision != model.DecisionCandidate {
		t.Fatalf("first package decision=%q, want candidate", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("second package decision=%q, want candidate", got.Packages[1].Decision)
	}
}
