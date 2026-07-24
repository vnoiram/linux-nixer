package validate

import (
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestScanReportAcceptsValidReport(t *testing.T) {
	result := ScanReport(model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.DecisionConfirmed},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/usr/local/bin/tool", Decision: model.DecisionCandidate},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Decision: model.DecisionMigrationNote},
		},
	})

	if !result.OK {
		t.Fatalf("valid report failed: %+v", result)
	}
	if result.Checked != 3 {
		t.Fatalf("checked=%d, want 3", result.Checked)
	}
}

func TestScanReportRejectsInvalidSchemaDecisionAndProtectedConfirmation(t *testing.T) {
	result := ScanReport(model.ScanReport{
		SchemaVersion: "linux-nixer.scan.v0",
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.Decision("maybe")},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", SecretRisk: true, Decision: model.DecisionConfirmed},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Decision: model.DecisionConfirmed},
		},
	})

	if result.OK {
		t.Fatalf("invalid report passed: %+v", result)
	}
	if len(result.Errors) != 4 {
		t.Fatalf("errors=%d, want 4: %+v", len(result.Errors), result.Errors)
	}
	text := FormatText(result)
	for _, want := range []string{"unsupported schema version", "unknown decision", "secret-risk finding cannot be confirmed", "stateful data cannot be confirmed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("formatted validation missing %q:\n%s", want, text)
		}
	}
}

func TestScanReportRejectsMalformedFixtureCorpus(t *testing.T) {
	cases := []struct {
		name   string
		report model.ScanReport
		wants  []string
	}{
		{
			name: "missing package ids",
			report: model.ScanReport{
				SchemaVersion: model.SchemaVersion,
				Packages:      []model.Package{{Decision: model.DecisionCandidate}},
			},
			wants: []string{"package manager is required", "package name is required"},
		},
		{
			name: "missing service ids",
			report: model.ScanReport{
				SchemaVersion: model.SchemaVersion,
				Services:      []model.Service{{Decision: model.DecisionCandidate}},
			},
			wants: []string{"service manager is required", "service name is required"},
		},
		{
			name: "missing item identity",
			report: model.ScanReport{
				SchemaVersion: model.SchemaVersion,
				Items:         []model.Item{{Kind: "custom-finding", Decision: model.DecisionCandidate}},
			},
			wants: []string{"item path or name is required"},
		},
		{
			name: "protected confirmed",
			report: model.ScanReport{
				SchemaVersion:  model.SchemaVersion,
				FilesystemDiff: []model.FileFinding{{Path: "/home/alice/.ssh/id_ed25519", SecretRisk: true, Decision: model.DecisionConfirmed}},
				StatefulData:   []model.FileFinding{{Path: "/var/lib/postgresql", Decision: model.DecisionConfirmed}},
			},
			wants: []string{"secret-risk finding cannot be confirmed", "stateful data cannot be confirmed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanReport(tc.report)
			if result.OK {
				t.Fatalf("malformed fixture passed: %+v", result)
			}
			text := FormatText(result)
			for _, want := range tc.wants {
				if !strings.Contains(text, want) {
					t.Fatalf("validation output missing %q:\n%s", want, text)
				}
			}
		})
	}
}
