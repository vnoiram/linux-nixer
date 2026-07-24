package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/scanner"
)

func TestPolicyConvertsToScanAndReviewOptions(t *testing.T) {
	autoSafe := true
	deep := true
	sudo := true
	p := Policy{
		SchemaVersion:       SchemaVersion,
		AutoSafe:            &autoSafe,
		ConfirmKinds:        []string{"service"},
		ExcludeKinds:        []string{"desktop-config"},
		TODOKinds:           []string{"git-source"},
		MigrationNoteKinds:  []string{"container"},
		ConfirmManagers:     []string{"apt"},
		ExcludePathPrefixes: []string{"/tmp"},
		IncludePaths:        []string{"/opt"},
		ExcludePaths:        []string{"/home/alice/Downloads"},
		Deep:                &deep,
		Sudo:                &sudo,
		Baseline:            "ubuntu:24.04",
	}

	scanOpts := p.ScanOptions(scanner.Options{Root: "/fixture", Includes: []string{"/srv"}})
	if !scanOpts.Deep || !scanOpts.UseSudo || scanOpts.BaselineID != "ubuntu:24.04" {
		t.Fatalf("unexpected scan options: %+v", scanOpts)
	}
	if got := scanOpts.Includes; len(got) != 2 || got[0] != "/opt" || got[1] != "/srv" {
		t.Fatalf("includes=%v, want policy then base", got)
	}
	if got := scanOpts.Excludes; len(got) != 1 || got[0] != "/home/alice/Downloads" {
		t.Fatalf("excludes=%v", got)
	}

	reviewOpts := p.ReviewOptions(review.Options{ConfirmKinds: []string{"os-config"}})
	if !reviewOpts.AutoSafe {
		t.Fatalf("autoSafe=false in %+v", reviewOpts)
	}
	if got := reviewOpts.ConfirmKinds; len(got) != 2 || got[0] != "service" || got[1] != "os-config" {
		t.Fatalf("confirmKinds=%v, want policy then base", got)
	}
	if got := reviewOpts.ConfirmManagers; len(got) != 1 || got[0] != "apt" {
		t.Fatalf("confirmManagers=%v", got)
	}
}

func TestLoadRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"schema.json": `{"schemaVersion":"linux-nixer.policy.v0"}`,
		"empty.json":  `{"schemaVersion":"linux-nixer.policy.v1","confirmKinds":[""]}`,
		"plugin.json": `{"schemaVersion":"linux-nixer.policy.v1","plugins":[""]}`,
		"type.json":   `{"schemaVersion":"linux-nixer.policy.v1","deep":"yes"}`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("expected %s to fail", name)
		}
	}
}

func TestTemplatePresetsSetExpectedFields(t *testing.T) {
	cases := []struct {
		preset       string
		wantAutoSafe bool
		wantConfirm  []string
		wantExclude  []string
	}{
		{"default", true, nil, nil},
		{"workstation", true, []string{"desktop-config", "shell-config", "user-config", "direnv"}, nil},
		{"server", true, []string{"service", "container", "os-config"}, []string{"desktop-config", "shell-plugin"}},
		{"developer-machine", true, []string{"dev-project", "git-source", "language-project", "shell-config", "direnv"}, nil},
		{"minimal-audit", false, nil, nil},
	}
	for _, tc := range cases {
		p, err := Template(tc.preset)
		if err != nil {
			t.Fatalf("Template(%q) error: %v", tc.preset, err)
		}
		if p.AutoSafe == nil || *p.AutoSafe != tc.wantAutoSafe {
			t.Fatalf("Template(%q).AutoSafe=%v, want %v", tc.preset, p.AutoSafe, tc.wantAutoSafe)
		}
		if !slices.Equal(p.ConfirmKinds, tc.wantConfirm) {
			t.Fatalf("Template(%q).ConfirmKinds=%v, want %v", tc.preset, p.ConfirmKinds, tc.wantConfirm)
		}
		if !slices.Equal(p.ExcludeKinds, tc.wantExclude) {
			t.Fatalf("Template(%q).ExcludeKinds=%v, want %v", tc.preset, p.ExcludeKinds, tc.wantExclude)
		}
		if len(p.ConfirmManagers) != 0 {
			t.Fatalf("Template(%q).ConfirmManagers=%v, want empty", tc.preset, p.ConfirmManagers)
		}
	}
}

func TestTemplateUnknownPresetReturnsError(t *testing.T) {
	p, err := Template("bogus")
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if p.SchemaVersion != "" {
		t.Fatalf("expected zero-value policy on error, got %+v", p)
	}
}

func TestDiffPresetsReportsListAndAutoSafeChanges(t *testing.T) {
	diff, err := DiffPresets("server", "minimal-audit")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.AutoSafeChanged || !diff.FromAutoSafe || diff.ToAutoSafe {
		t.Fatalf("unexpected autoSafe diff: %+v", diff)
	}
	fields := map[string]FieldDiff{}
	for _, field := range diff.Fields {
		fields[field.Name] = field
	}
	confirm := fields["confirmKinds"]
	if !slices.Equal(confirm.Removed, []string{"service", "container", "os-config"}) {
		t.Fatalf("unexpected confirmKinds diff: %+v", confirm)
	}
	exclude := fields["excludeKinds"]
	if !slices.Equal(exclude.Removed, []string{"desktop-config", "shell-plugin"}) {
		t.Fatalf("unexpected excludeKinds diff: %+v", exclude)
	}
}

func TestLintReportsDuplicatesUnknownKindsAndContradictions(t *testing.T) {
	ok := Lint(Policy{SchemaVersion: SchemaVersion, ConfirmKinds: []string{"service"}})
	if !ok.OK || len(ok.Errors) != 0 || len(ok.Warnings) != 0 {
		t.Fatalf("valid lint result should be clean: %+v", ok)
	}

	got := Lint(Policy{
		SchemaVersion: SchemaVersion,
		ConfirmKinds:  []string{"service", "service", "typo-kind"},
		ExcludeKinds:  []string{"service"},
	})
	if got.OK {
		t.Fatalf("contradictory policy should fail lint: %+v", got)
	}
	if len(got.Errors) != 1 || !strings.Contains(got.Errors[0].Message, "contradictory") {
		t.Fatalf("expected contradictory-kind error: %+v", got)
	}
	if len(got.Warnings) < 2 {
		t.Fatalf("expected duplicate and unknown-kind warnings: %+v", got)
	}
}

func TestTemplateEmptyPresetMatchesCurrentDefault(t *testing.T) {
	empty, err := Template("")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Template("default")
	if err != nil {
		t.Fatal(err)
	}
	if empty.AutoSafe == nil || !*empty.AutoSafe {
		t.Fatalf("Template(\"\").AutoSafe=%v, want true", empty.AutoSafe)
	}
	if len(empty.ConfirmKinds) != 0 || len(empty.ExcludeKinds) != 0 {
		t.Fatalf("Template(\"\") should have no confirm/exclude kinds: %+v", empty)
	}
	if named.AutoSafe == nil || *empty.AutoSafe != *named.AutoSafe {
		t.Fatalf("Template(\"\") and Template(\"default\") should match: %+v vs %+v", empty, named)
	}
}

func TestPresetNamesAreAllValidTemplateInputs(t *testing.T) {
	for _, name := range PresetNames {
		if _, err := Template(name); err != nil {
			t.Fatalf("PresetNames contains %q, but Template(%q) errored: %v", name, name, err)
		}
	}
}

func TestMergeDeduplicatesWithStableOrder(t *testing.T) {
	got := Merge([]string{"b", "a", "c"}, []string{"a", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("merge=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merge=%v, want %v", got, want)
		}
	}
}

func TestFormatDecisionConflictsMarkdown(t *testing.T) {
	result := CheckDecisions(review.DecisionSet{
		SchemaVersion: review.DecisionsSchemaVersion,
		Entries: []review.DecisionEntry{
			{Domain: "service", Key: "systemd:sshd.service", Decision: model.DecisionExcluded},
		},
	}, Policy{ConfirmKinds: []string{"service"}})

	got := FormatDecisionConflictsMarkdown(result)
	for _, want := range []string{
		"# Decision conflict report",
		"- Checked decisions: 1",
		"## Warnings",
		"`service:systemd:sshd.service`: decision \"excluded\" conflicts with current policy",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("conflict report missing %q:\n%s", want, got)
		}
	}
}
