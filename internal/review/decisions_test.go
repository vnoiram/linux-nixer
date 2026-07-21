package review

import (
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestExportDecisionsSkipsCandidatesAndUnsetDecisions(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.DecisionConfirmed},
			{Manager: "apt", Name: "unset"},
			{Manager: "apt", Name: "candidate", Decision: model.DecisionCandidate},
		},
	}

	set := ExportDecisions(report)

	if len(set.Entries) != 1 {
		t.Fatalf("entries=%v, want exactly 1", set.Entries)
	}
	if set.Entries[0].Domain != "package" || set.Entries[0].Key != "apt:curl" || set.Entries[0].Decision != model.DecisionConfirmed {
		t.Fatalf("unexpected entry: %+v", set.Entries[0])
	}
	if set.SchemaVersion != DecisionsSchemaVersion {
		t.Fatalf("schemaVersion=%q, want %q", set.SchemaVersion, DecisionsSchemaVersion)
	}
}

func TestExportDecisionsCoversAllPackageSources(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{{Manager: "apt", Name: "curl", Decision: model.DecisionConfirmed}},
		Languages: model.Languages{
			NPM:   []model.Package{{Manager: "npm", Name: "typescript", Decision: model.DecisionConfirmed}},
			Conda: []model.Package{{Manager: "conda", Name: "numpy", Decision: model.DecisionExcluded}},
			Cargo: []model.Package{{Manager: "cargo", Name: "starship", Decision: model.DecisionConfirmed}},
			Gem:   []model.Package{{Manager: "gem", Name: "bundler", Decision: model.DecisionTODO}},
			Go:    []model.Package{{Manager: "go-install", Name: "gopls", Decision: model.DecisionConfirmed}},
			Python: []model.PythonEnv{{
				Path: "/home/alice/.local/pipx/venvs/ruff",
				Kind: "pipx",
				Packages: []model.Package{
					{Manager: "pipx", Name: "ruff", Decision: model.DecisionConfirmed},
				},
			}},
		},
	}

	set := ExportDecisions(report)

	want := map[string]model.Decision{
		"apt:curl":         model.DecisionConfirmed,
		"npm:typescript":   model.DecisionConfirmed,
		"conda:numpy":      model.DecisionExcluded,
		"cargo:starship":   model.DecisionConfirmed,
		"gem:bundler":      model.DecisionTODO,
		"go-install:gopls": model.DecisionConfirmed,
		"pipx:ruff":        model.DecisionConfirmed,
	}
	if len(set.Entries) != len(want) {
		t.Fatalf("entries=%+v, want %d entries", set.Entries, len(want))
	}
	for _, e := range set.Entries {
		if e.Domain != "package" {
			t.Fatalf("unexpected domain %q for %+v", e.Domain, e)
		}
		if wantDecision, ok := want[e.Key]; !ok || wantDecision != e.Decision {
			t.Fatalf("unexpected entry %+v", e)
		}
	}
}

func TestApplyDecisionsSeedsMatchingFindingsOnly(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl"},
			{Manager: "apt", Name: "untouched"},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service"},
		},
	}
	set := DecisionSet{
		SchemaVersion: DecisionsSchemaVersion,
		Entries: []DecisionEntry{
			{Domain: "package", Key: "apt:curl", Decision: model.DecisionConfirmed},
			{Domain: "package", Key: "apt:gone", Decision: model.DecisionConfirmed},
			{Domain: "service", Key: "systemd:app.service", Decision: model.DecisionExcluded},
		},
	}

	got := ApplyDecisions(report, set)

	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("curl decision=%q, want confirmed", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != "" {
		t.Fatalf("untouched decision=%q, want empty (no matching entry)", got.Packages[1].Decision)
	}
	if got.Services[0].Decision != model.DecisionExcluded {
		t.Fatalf("service decision=%q, want excluded", got.Services[0].Decision)
	}
}

func TestApplyDecisionsTakesPrecedenceOverPolicyConfirmKinds(t *testing.T) {
	report := model.ScanReport{
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Path: "/etc/systemd/system/app.service"},
		},
	}
	set := DecisionSet{
		SchemaVersion: DecisionsSchemaVersion,
		Entries: []DecisionEntry{
			{Domain: "service", Key: "systemd:app.service", Decision: model.DecisionConfirmed},
		},
	}
	seeded := ApplyDecisions(report, set)

	got := Apply(seeded, Options{ExcludeKinds: []string{"service"}})

	if got.Services[0].Decision != model.DecisionConfirmed {
		t.Fatalf("service decision=%q, want confirmed (imported decision should win over policy excludeKinds)", got.Services[0].Decision)
	}
}
