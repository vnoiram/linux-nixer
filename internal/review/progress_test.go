package review

import (
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func findEntry(entries []ProgressEntry, domain, key string) (ProgressEntry, bool) {
	for _, e := range entries {
		if e.Domain == domain && e.Key == key {
			return e, true
		}
	}
	return ProgressEntry{}, false
}

func TestComputeProgressCategorizesChanges(t *testing.T) {
	previous := DecisionSet{
		SchemaVersion: DecisionsSchemaVersion,
		Entries: []DecisionEntry{
			{Domain: "package", Key: "apt:curl", Decision: model.DecisionConfirmed},
			{Domain: "service", Key: "systemd:app.service", Decision: model.DecisionConfirmed},
			{Domain: "container", Key: "docker:web", Decision: model.DecisionExcluded},
		},
	}
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.DecisionConfirmed},      // unchanged
			{Manager: "apt", Name: "unrelated", Decision: model.DecisionCandidate}, // stillPending
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Decision: model.DecisionExcluded}, // changed
		},
		// container "docker:web" is entirely absent -> removed
		GitSources: []model.GitSource{
			{Path: "/home/alice/app", Decision: model.DecisionConfirmed}, // newly decided
		},
	}

	got := ComputeProgress(report, previous)

	if got.PreviousDecided != 3 {
		t.Fatalf("previousDecided=%d, want 3", got.PreviousDecided)
	}
	if got.CurrentDecided != 3 {
		t.Fatalf("currentDecided=%d, want 3 (curl, app.service, git-source)", got.CurrentDecided)
	}
	if got.StillPending != 1 {
		t.Fatalf("stillPending=%d, want 1", got.StillPending)
	}

	if len(got.NewlyDecided) != 1 {
		t.Fatalf("newlyDecided=%+v, want 1 entry", got.NewlyDecided)
	}
	if e, ok := findEntry(got.NewlyDecided, "git-source", "/home/alice/app"); !ok || e.CurrentDecision != model.DecisionConfirmed {
		t.Fatalf("unexpected newlyDecided: %+v", got.NewlyDecided)
	}

	if len(got.Changed) != 1 {
		t.Fatalf("changed=%+v, want 1 entry", got.Changed)
	}
	if e, ok := findEntry(got.Changed, "service", "systemd:app.service"); !ok || e.PreviousDecision != model.DecisionConfirmed || e.CurrentDecision != model.DecisionExcluded {
		t.Fatalf("unexpected changed: %+v", got.Changed)
	}

	if len(got.Removed) != 1 {
		t.Fatalf("removed=%+v, want 1 entry", got.Removed)
	}
	if e, ok := findEntry(got.Removed, "container", "docker:web"); !ok || e.PreviousDecision != model.DecisionExcluded {
		t.Fatalf("unexpected removed: %+v", got.Removed)
	}

	if len(got.Regressed) != 0 {
		t.Fatalf("regressed=%+v, want none", got.Regressed)
	}

	// curl should not appear in any change bucket at all (unchanged).
	for _, bucket := range [][]ProgressEntry{got.NewlyDecided, got.Changed, got.Regressed, got.Removed} {
		if _, ok := findEntry(bucket, "package", "apt:curl"); ok {
			t.Fatalf("unchanged apt:curl should not appear in any bucket: %+v", bucket)
		}
	}
}

func TestComputeProgressDetectsRegression(t *testing.T) {
	previous := DecisionSet{
		SchemaVersion: DecisionsSchemaVersion,
		Entries: []DecisionEntry{
			{Domain: "package", Key: "apt:curl", Decision: model.DecisionConfirmed},
		},
	}
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.DecisionCandidate},
		},
	}

	got := ComputeProgress(report, previous)

	if len(got.Regressed) != 1 {
		t.Fatalf("regressed=%+v, want 1 entry", got.Regressed)
	}
	if e, ok := findEntry(got.Regressed, "package", "apt:curl"); !ok || e.PreviousDecision != model.DecisionConfirmed {
		t.Fatalf("unexpected regressed entry: %+v", got.Regressed)
	}
	if len(got.Removed) != 0 {
		t.Fatalf("removed=%+v, want none (finding is still present, just regressed)", got.Removed)
	}
}

func TestFormatProgressTimelineMarkdown(t *testing.T) {
	got := FormatProgressTimelineMarkdown(Progress{
		PreviousDecided: 1,
		CurrentDecided:  2,
		StillPending:    3,
		NewlyDecided: []ProgressEntry{{
			Domain:          "package",
			Key:             "apt:curl",
			CurrentDecision: model.DecisionConfirmed,
		}},
		Changed: []ProgressEntry{{
			Domain:           "service",
			Key:              "systemd:app.service",
			PreviousDecision: model.DecisionConfirmed,
			CurrentDecision:  model.DecisionExcluded,
		}},
	})
	for _, want := range []string{
		"# Progress timeline",
		"## 1. Newly decided",
		"package `apt:curl` became confirmed",
		"## 2. Changed decisions",
		"service `systemd:app.service` changed from confirmed to excluded",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("timeline missing %q:\n%s", want, got)
		}
	}
}
