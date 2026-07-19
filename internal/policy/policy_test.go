package policy

import (
	"os"
	"path/filepath"
	"testing"

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
