package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/baseline"
	"github.com/vnoiram/linux-nixer/internal/model"
	policypkg "github.com/vnoiram/linux-nixer/internal/policy"
)

func TestRunReviewInteractiveWritesReviewedJSON(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", outPath, "--interactive"}, strings.NewReader("c\n"), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("decision=%q, want confirmed", got.Packages[0].Decision)
	}
	if !strings.Contains(stdout.String(), "choose c=confirmed") {
		t.Fatalf("stdout missing prompt: %s", stdout.String())
	}
}

func TestRunReviewWritesPolicyExplanation(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "reviewed.json")
	explainPath := filepath.Join(dir, "explain.md")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", outPath, "--auto-safe", "--explain-policy", explainPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(explainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "`apt:curl`: confirmed - confirmed by auto-safe package mapping") {
		t.Fatalf("unexpected explanation:\n%s", got)
	}
	if !strings.Contains(stdout.String(), "wrote policy explanation") {
		t.Fatalf("stdout missing explanation path: %s", stdout.String())
	}
}

func TestRunReviewWritesDecisionsReport(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "reviewed.json")
	reportPath := filepath.Join(dir, "decisions.md")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", outPath, "--auto-safe", "--export-decisions-report", reportPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "`package:apt:curl`") || !strings.Contains(string(got), "## confirmed (1)") {
		t.Fatalf("unexpected decisions report:\n%s", got)
	}
	if !strings.Contains(stdout.String(), "wrote decisions report") {
		t.Fatalf("stdout missing report path: %s", stdout.String())
	}
}

func TestRunReviewInteractiveFilter(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
			{Manager: "apt", Name: "custom-tool"},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", outPath, "--interactive", "--filter", "unmapped"}, strings.NewReader("c\n"), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var got model.ScanReport
	readScan(t, outPath, &got)
	if got.Packages[0].Decision != model.DecisionCandidate || got.Packages[1].Decision != model.DecisionConfirmed {
		t.Fatalf("unexpected filtered decisions: %+v", got.Packages)
	}
	if strings.Contains(stdout.String(), "apt curl") || !strings.Contains(stdout.String(), "custom-tool") {
		t.Fatalf("unexpected filtered prompt output:\n%s", stdout.String())
	}
}

func TestRunVersionWritesBuildVersion(t *testing.T) {
	oldVersion := version
	version = "v9.8.7"
	t.Cleanup(func() { version = oldVersion })

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "v9.8.7" {
		t.Fatalf("version=%q, want v9.8.7", got)
	}
}

func TestRunVersionFullPrintsMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	version, commit, date = "v9.8.7", "abc1234", "2026-07-21T00:00:00Z"
	t.Cleanup(func() { version, commit, date = oldVersion, oldCommit, oldDate })

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"version", "--full"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "version=v9.8.7 commit=abc1234 built=2026-07-21T00:00:00Z" {
		t.Fatalf("version --full=%q, want version=v9.8.7 commit=abc1234 built=2026-07-21T00:00:00Z", got)
	}
}

func TestRunCaptureWritesSessionMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	version, commit, date = "v9.8.7", "abc1234", "2026-07-24T00:00:00Z"
	t.Cleanup(func() { version, commit, date = oldVersion, oldCommit, oldDate })

	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "capture")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"capture", "--root", root, "--preset", "minimal-audit", "--include", "/opt", "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var got captureSessionMetadata
	if err := readJSON(filepath.Join(out, "session.json"), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != "linux-nixer.capture-session.v1" || got.Version != "v9.8.7" || got.Commit != "abc1234" || got.Built != "2026-07-24T00:00:00Z" {
		t.Fatalf("unexpected version metadata: %+v", got)
	}
	if got.Scan.Root != root || got.Scan.Preset != "minimal-audit" || got.Scan.PluginTimeout != "30s" {
		t.Fatalf("unexpected scan metadata: %+v", got.Scan)
	}
	if !containsString(got.Scan.IncludePaths, "/opt") || !containsString(got.Artifacts, "nix-config/") {
		t.Fatalf("missing include/artifact metadata: %+v", got)
	}
	if got.StartedAt == "" || got.FinishedAt == "" {
		t.Fatalf("timestamps should be recorded: %+v", got)
	}
}

func TestRunHelpIncludesCaptureSummaryAndVersion(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"help"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"linux-nixer capture --out DIR", "linux-nixer validate --scan reviewed.json", "linux-nixer summary --scan reviewed.json", "linux-nixer help <command>", "linux-nixer version"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunMigrationGuide(t *testing.T) {
	for _, args := range [][]string{{"guide"}, {"help", "guide"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout bytes.Buffer
			err := run(context.Background(), args, strings.NewReader(""), &stdout, &stdout)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"linux-nixer migration guide",
				"linux-nixer capture --out linux-nixer-output",
				"linux-nixer review --scan scan.json --out reviewed.json",
				"linux-nixer validate --scan reviewed.json --strict",
				"Generated Nix only uses confirmed findings",
			} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("guide missing %q:\n%s", want, stdout.String())
				}
			}
		})
	}
}

func TestRunCommandHelpTopics(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		wants []string
	}{
		{
			name: "help scan",
			args: []string{"help", "scan"},
			wants: []string{
				"linux-nixer scan",
				"Examples:",
				"--baseline ID",
				"--preset NAME",
				"Policy include/exclude/plugin lists",
			},
		},
		{
			name: "capture flag help",
			args: []string{"capture", "--help"},
			wants: []string{
				"linux-nixer capture",
				"Artifacts:",
				"DIR/scan.json",
				"DIR/nix-config/",
				"--fail-on-pending",
				"Explicit CLI boolean and string flags override policy values",
			},
		},
		{
			name: "policy init flag help",
			args: []string{"policy", "init", "--help"},
			wants: []string{
				"linux-nixer policy init",
				"schemaVersion",
				"linux-nixer.policy.v1",
				"--out PATH",
			},
		},
		{
			name: "validate short help",
			args: []string{"validate", "-h"},
			wants: []string{
				"linux-nixer validate",
				"--strict",
				"Reject unknown JSON fields",
			},
		},
		{
			name: "baseline create help",
			args: []string{"help", "baseline", "create"},
			wants: []string{
				"linux-nixer baseline create",
				"--distro NAME",
				"filesystem differences",
			},
		},
		{
			name: "baseline fetch help",
			args: []string{"help", "baseline", "fetch"},
			wants: []string{
				"linux-nixer baseline fetch",
				"--backend NAME",
				"docker or podman",
				"no hand-maintained package data",
			},
		},
		{
			name: "baseline list help",
			args: []string{"help", "baseline", "list"},
			wants: []string{
				"linux-nixer baseline list",
				"curated distro/release pairs",
				"baseline list",
			},
		},
		{
			name: "baseline check help",
			args: []string{"help", "baseline", "check"},
			wants: []string{
				"linux-nixer baseline check",
				"--fail-on-drift",
				"never modifies the catalog",
			},
		},
		{
			name: "review help",
			args: []string{"review", "-h"},
			wants: []string{
				"linux-nixer review",
				"c/k/t/m/x/s/n/bt/bx/bk/bm/q",
				"--pending-only",
				"--filter NAME",
				"Policy decisions are applied first",
			},
		},
		{
			name: "summary help",
			args: []string{"summary", "--help"},
			wants: []string{
				"linux-nixer summary",
				"--fail-on-pending",
				"candidate or todo findings remain",
			},
		},
		{
			name: "generate help",
			args: []string{"generate", "--help"},
			wants: []string{
				"linux-nixer generate",
				"--scan PATH",
				"--out DIR",
				"--format-nix",
			},
		},
		{
			name: "doctor help",
			args: []string{"doctor", "--help"},
			wants: []string{
				"linux-nixer doctor",
				"--vm",
				"--boot",
				"--boot-readiness",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := run(context.Background(), tt.args, strings.NewReader(""), &stdout, &stdout)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.wants {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("help missing %q:\n%s", want, stdout.String())
				}
			}
		})
	}
}

func TestRunCommandHelpUnknownTopicFails(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"help", "unknown"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected unknown help topic to fail")
	}
	if !strings.Contains(err.Error(), "unknown help topic") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunCLIErrorHints(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "unknown command",
			args: []string{"bogus"},
			want: "linux-nixer help",
		},
		{
			name: "scan missing out",
			args: []string{"scan"},
			want: "linux-nixer scan --out scan.json",
		},
		{
			name: "capture missing out",
			args: []string{"capture"},
			want: "linux-nixer capture --out linux-nixer-output",
		},
		{
			name: "validate missing subject",
			args: []string{"validate"},
			want: "linux-nixer validate --scan reviewed.json --strict",
		},
		{
			name: "doctor missing project",
			args: []string{"doctor"},
			want: "linux-nixer doctor --project nix-config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := run(context.Background(), tt.args, strings.NewReader(""), &stdout, &stdout)
			if err == nil {
				t.Fatal("expected command to fail")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error missing hint %q: %v", tt.want, err)
			}
		})
	}
}

func TestRunValidateWritesDecisionConflictReport(t *testing.T) {
	dir := t.TempDir()
	decisionsPath := filepath.Join(dir, "decisions.json")
	policyPath := filepath.Join(dir, "policy.json")
	conflictsPath := filepath.Join(dir, "conflicts.md")
	writeJSONFile(t, decisionsPath, map[string]any{
		"schemaVersion": "linux-nixer.decisions.v1",
		"entries": []map[string]string{
			{"domain": "service", "key": "systemd:sshd.service", "decision": "excluded"},
		},
	})
	writeJSONFile(t, policyPath, map[string]any{
		"schemaVersion": "linux-nixer.policy.v1",
		"confirmKinds":  []string{"service"},
	})

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"validate", "--decisions", decisionsPath, "--policy", policyPath, "--conflicts-out", conflictsPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(conflictsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "decision \"excluded\" conflicts with current policy") {
		t.Fatalf("unexpected conflicts report:\n%s", got)
	}
}

func TestRunGenerateFormatNixWarnsWhenFormatterMissing(t *testing.T) {
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })

	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	out := filepath.Join(dir, "nix-config")
	writeScan(t, scanPath, model.ScanReport{SchemaVersion: model.SchemaVersion})

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"generate", "--scan", scanPath, "--out", out, "--format-nix"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "flake.nix")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "warning: --format-nix requested") {
		t.Fatalf("stdout missing formatter warning: %s", stdout.String())
	}
}

func TestRunValidateWritesTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.DecisionConfirmed},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"validate", "--scan", scanPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "valid scan") {
		t.Fatalf("validate text missing valid result:\n%s", stdout.String())
	}

	stdout.Reset()
	err = run(context.Background(), []string{"validate", "--scan", scanPath, "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid validate json: %v\n%s", err, stdout.String())
	}
	if !got.OK {
		t.Fatalf("validate json ok=false: %s", stdout.String())
	}
}

func TestRunValidateFailsInvalidScanAndStrictUnknownField(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", Decision: model.Decision("maybe")},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"validate", "--scan", scanPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected invalid scan to fail")
	}
	if !strings.Contains(stdout.String(), "unknown decision") {
		t.Fatalf("validate text missing unknown decision:\n%s", stdout.String())
	}

	strictPath := filepath.Join(dir, "strict.json")
	if err := os.WriteFile(strictPath, []byte(`{"schemaVersion":"linux-nixer.scan.v1","unexpected":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err = run(context.Background(), []string{"validate", "--scan", strictPath, "--strict", "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected strict unknown field to fail")
	}
	if !strings.Contains(stdout.String(), "unknown field") {
		t.Fatalf("strict validate output missing unknown field:\n%s", stdout.String())
	}
}

func TestRunValidateChecksDecisionsAgainstPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","confirmKinds":["service"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	decisionsPath := filepath.Join(dir, "decisions.json")
	decisionsJSON := `{"schemaVersion":"linux-nixer.decisions.v1","entries":[{"domain":"service","key":"systemd:legacy.service","decision":"excluded"}]}`
	if err := os.WriteFile(decisionsPath, []byte(decisionsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"validate", "--decisions", decisionsPath, "--policy", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("stale decision warnings should not fail the command, got %v:\n%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), `conflicts with current policy for kind "service"`) {
		t.Fatalf("expected stale-decision warning, got:\n%s", stdout.String())
	}
}

func TestRunValidateDecisionsRequiresPolicy(t *testing.T) {
	dir := t.TempDir()
	decisionsPath := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(decisionsPath, []byte(`{"schemaVersion":"linux-nixer.decisions.v1","entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"validate", "--decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected --decisions without --policy to fail")
	}
	if !strings.Contains(err.Error(), "requires --policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writePluginFixture(t *testing.T, path, itemsJSON string) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		"cat <<'EOF'\n" +
		`{"schemaVersion":"linux-nixer.scan.v1","items":[` + itemsJSON + `]}` + "\n" +
		"EOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRunPluginCheckSucceedsForValidPlugin(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "good-plugin.sh")
	writePluginFixture(t, pluginPath, `{"kind":"custom-finding","path":"/opt/thing","reason":"found by plugin"}`)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"plugin", "check", "--plugin", pluginPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("expected success, got %v:\n%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "plugin OK") {
		t.Fatalf("expected success text, got:\n%s", stdout.String())
	}

	stdout.Reset()
	err = run(context.Background(), []string{"plugin", "check", "--plugin", pluginPath, "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("expected success, got %v:\n%s", err, stdout.String())
	}
	var got struct {
		OK      bool `json:"ok"`
		Checked int  `json:"checked"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid plugin check json: %v\n%s", err, stdout.String())
	}
	if !got.OK || got.Checked != 1 {
		t.Fatalf("unexpected plugin check json: %+v", got)
	}
}

func TestRunPluginCheckFailsForInvalidItem(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "bad-item-plugin.sh")
	writePluginFixture(t, pluginPath, `{"path":"/opt/thing","reason":"missing kind"}`)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"plugin", "check", "--plugin", pluginPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected failure for item missing kind")
	}
	if !strings.Contains(stdout.String(), "item kind is required") {
		t.Fatalf("expected validate.ScanReport's item check to surface, got:\n%s", stdout.String())
	}
}

func TestRunPluginCheckFailsForBrokenProcess(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "missing-plugin.sh")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"plugin", "check", "--plugin", pluginPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected failure for a nonexistent plugin executable")
	}
	if !strings.Contains(stdout.String(), "plugin check failed") {
		t.Fatalf("expected process failure text, got:\n%s", stdout.String())
	}
}

func TestRunDoctorFailsWhenChecksFail(t *testing.T) {
	if _, err := exec.LookPath("nix"); err == nil {
		t.Skip("nix is installed in this environment; this test relies on the missing-project-files check failing on its own")
	}
	dir := t.TempDir()

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"doctor", "--project", dir}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected doctor to fail for a project missing every generated file")
	}
	if !strings.Contains(err.Error(), "doctor checks failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
		t.Fatalf("expected valid result JSON on stdout even on failure: %v\n%s", jsonErr, stdout.String())
	}
	if result.OK {
		t.Fatalf("result JSON says ok=true despite the error: %s", stdout.String())
	}
}

func TestRunPolicyInitWritesParseablePolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "linux-nixer-policy.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "init", "--out", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote policy:") {
		t.Fatalf("policy init stdout missing path:\n%s", stdout.String())
	}
	p, err := policypkg.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != policypkg.SchemaVersion || p.AutoSafe == nil || !*p.AutoSafe {
		t.Fatalf("unexpected policy template: %+v", p)
	}
}

func TestRunPolicyInitWithPresetWritesConfirmKinds(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "server-policy.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "init", "--preset", "server", "--out", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypkg.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	wantConfirm := []string{"service", "container", "os-config"}
	if len(p.ConfirmKinds) != len(wantConfirm) {
		t.Fatalf("confirmKinds=%v, want %v", p.ConfirmKinds, wantConfirm)
	}
	for i, k := range wantConfirm {
		if p.ConfirmKinds[i] != k {
			t.Fatalf("confirmKinds=%v, want %v", p.ConfirmKinds, wantConfirm)
		}
	}
	wantExclude := []string{"desktop-config", "shell-plugin"}
	if len(p.ExcludeKinds) != len(wantExclude) {
		t.Fatalf("excludeKinds=%v, want %v", p.ExcludeKinds, wantExclude)
	}
	for i, k := range wantExclude {
		if p.ExcludeKinds[i] != k {
			t.Fatalf("excludeKinds=%v, want %v", p.ExcludeKinds, wantExclude)
		}
	}
}

func TestRunPolicyDiffWritesTextAndJSON(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "diff", "--from", "default", "--to", "developer-machine"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Policy preset diff: default -> developer-machine",
		"autoSafe: unchanged (true)",
		"confirmKinds added=dev-project,git-source,language-project,shell-config,direnv",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("policy diff text missing %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	err = run(context.Background(), []string{"policy", "diff", "--from", "server", "--to", "minimal-audit", "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var got policypkg.PresetDiff
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid policy diff json: %v\n%s", err, stdout.String())
	}
	if got.From != "server" || got.To != "minimal-audit" || !got.AutoSafeChanged || got.ToAutoSafe {
		t.Fatalf("unexpected policy diff json: %+v", got)
	}
}

func TestRunPolicyDiffRequiresPresets(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "diff", "--from", "server"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected missing --to to fail")
	}
	if !strings.Contains(err.Error(), "requires --from and --to") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPolicyLintWritesTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	cleanPath := filepath.Join(dir, "clean-policy.json")
	if err := os.WriteFile(cleanPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","confirmKinds":["service"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"policy", "lint", "--policy", cleanPath}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "policy lint OK") {
		t.Fatalf("policy lint text missing OK:\n%s", stdout.String())
	}

	badPath := filepath.Join(dir, "bad-policy.json")
	if err := os.WriteFile(badPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","confirmKinds":["service","service","typo-kind"],"excludeKinds":["service"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err := run(context.Background(), []string{"policy", "lint", "--policy", badPath, "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected contradictory policy lint to fail")
	}
	var got policypkg.LintResult
	if jsonErr := json.Unmarshal(stdout.Bytes(), &got); jsonErr != nil {
		t.Fatalf("policy lint --json did not emit JSON: %v\n%s", jsonErr, stdout.String())
	}
	if got.OK || len(got.Errors) == 0 || len(got.Warnings) < 2 {
		t.Fatalf("unexpected policy lint JSON: %+v", got)
	}
}

func TestRunPolicyExamplesWritesLoadableProfiles(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "examples")
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"policy", "examples", "--out", out}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"home-workstation.json", "server.json", "dev-laptop.json", "audit-only.json"} {
		path := filepath.Join(out, file)
		if !strings.Contains(stdout.String(), path) {
			t.Fatalf("stdout missing written path %s:\n%s", path, stdout.String())
		}
		p, err := policypkg.Load(path)
		if err != nil {
			t.Fatalf("example %s was not loadable: %v", file, err)
		}
		if p.SchemaVersion != policypkg.SchemaVersion {
			t.Fatalf("example %s schemaVersion=%q", file, p.SchemaVersion)
		}
	}
}

func TestRunPolicyInitRejectsUnknownPreset(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bogus-policy.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "init", "--preset", "bogus", "--out", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), "unknown policy preset") || !strings.Contains(err.Error(), "linux-nixer policy init --preset workstation") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(policyPath); !os.IsNotExist(statErr) {
		t.Fatalf("policy file should not be written for unknown preset, stat err=%v", statErr)
	}
}

func TestRunPolicyLoadMissingPathHasHint(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	writeScan(t, scanPath, model.ScanReport{SchemaVersion: model.SchemaVersion})

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", filepath.Join(dir, "reviewed.json"), "--policy", filepath.Join(dir, "missing-policy.json")}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected missing policy file to fail")
	}
	if !strings.Contains(err.Error(), "linux-nixer policy init --out linux-nixer-policy.json") {
		t.Fatalf("error missing policy hint: %v", err)
	}
}

func TestRunPolicyInitWritesStdoutForDash(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "init", "--out", "-"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var got policypkg.Policy
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("policy init stdout was not JSON: %v\n%s", err, stdout.String())
	}
	if got.SchemaVersion != policypkg.SchemaVersion {
		t.Fatalf("schemaVersion=%q, want %q", got.SchemaVersion, policypkg.SchemaVersion)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "-")); !os.IsNotExist(statErr) {
		t.Fatalf("policy init --out - should not create '-' file, stat err=%v", statErr)
	}
}

func TestRunBaselineFetchRequiresDistroAndRelease(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "fetch", "--distro", "ubuntu"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error when --release is missing")
	}
	if !strings.Contains(err.Error(), "requires --distro and --release") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBaselineUnknownSubcommandFails(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "bogus"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for unknown baseline subcommand")
	}
	if !strings.Contains(err.Error(), "baseline create") || !strings.Contains(err.Error(), "baseline fetch") || !strings.Contains(err.Error(), "baseline import") || !strings.Contains(err.Error(), "baseline list") || !strings.Contains(err.Error(), "baseline check") {
		t.Fatalf("error should mention all five subcommands: %v", err)
	}
}

func TestRunBaselineCheckReportsPerEntryErrorsWithoutRealBackend(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "check", "--backend", "linux-nixer-nonexistent-backend-xyz"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("baseline check should report per-entry errors, not fail outright: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "error:") {
		t.Fatalf("expected per-entry errors in output since the backend doesn't exist, got: %q", out)
	}
}

func TestRunBaselineCheckFailOnDriftFailsOnError(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "check", "--backend", "linux-nixer-nonexistent-backend-xyz", "--fail-on-drift"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected --fail-on-drift to fail when every entry errors")
	}
}

func TestRunBaselineListPrintsCatalogEntries(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"baseline", "list"}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatalf("baseline list failed: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "ubuntu 24.04") || !strings.Contains(out, "debian 12") {
		t.Fatalf("expected catalog entries in output, got: %q", out)
	}
}

func TestRunBaselineListJSONOutput(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"baseline", "list", "--json"}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatalf("baseline list --json failed: %v", err)
	}
	var entries []baseline.CatalogEntry
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("baseline list --json did not produce valid JSON: %v\noutput: %s", err, stdout.String())
	}
	var found bool
	for _, e := range entries {
		if e.Distro == "ubuntu" && e.Release == "24.04" {
			found = true
			if e.Image == "" || e.Digest == "" {
				t.Fatalf("ubuntu 24.04 entry missing image/digest: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("expected an ubuntu 24.04 entry in JSON output: %s", stdout.String())
	}
}

func TestRunBaselineFetchRejectsDistroNotInCatalog(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "fetch", "--distro", "alpine", "--release", "3.19"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for a distro/release not in the baseline catalog")
	}
	if !strings.Contains(err.Error(), "baseline catalog") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBaselineFetchOfflineUsesBundledManifest(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "ubuntu-24.04.json")
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "fetch", "--distro", "ubuntu", "--release", "24.04", "--offline", "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("offline fetch failed: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), `"distro": "ubuntu"`) {
		t.Fatalf("output does not look like a manifest: %s", data)
	}
}

func TestRunBaselineFetchOfflineRejectsUnbundledDistro(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "fetch", "--distro", "alpine", "--release", "3.19", "--offline"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for a distro/release with no bundled manifest")
	}
	if !strings.Contains(err.Error(), "no bundled manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBaselineImportBuildsManifestFromFile(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "rootfs.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	content := []byte("myhost\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/hostname", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "baseline.json")
	var stdout bytes.Buffer
	err = run(context.Background(), []string{"baseline", "import", "--distro", "ubuntu", "--release", "24.04", "--tar", tarPath, "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote baseline:") {
		t.Fatalf("baseline import stdout missing path:\n%s", stdout.String())
	}

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/etc/hostname") {
		t.Fatalf("baseline JSON missing /etc/hostname: %s", string(b))
	}
	if !strings.Contains(string(b), "\"source\": \"tar:"+tarPath+"\"") {
		t.Fatalf("baseline JSON missing tar source: %s", string(b))
	}
}

func TestRunBaselineImportRequiresTar(t *testing.T) {
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"baseline", "import", "--distro", "ubuntu", "--release", "24.04"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error when --tar is missing")
	}
	if !strings.Contains(err.Error(), "requires --distro, --release, and --tar") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunScanInvokesPluginScanner(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "my-plugin.sh")
	script := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		"cat <<'EOF'\n" +
		`{"schemaVersion":"linux-nixer.scan.v1","items":[{"kind":"plugin-finding","name":"thing","path":"/opt/plugin-thing","reason":"found by plugin"}]}` + "\n" +
		"EOF\n"
	if err := os.WriteFile(pluginPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "scan.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--plugin", pluginPath, "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	found := false
	for _, item := range got.Items {
		if item.Kind == "plugin-finding" && item.Path == "/opt/plugin-thing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected plugin-contributed item in scan output: %+v", got.Items)
	}
	if countWarnings(got.Warnings, "plugin", "arbitrary executables") != 1 {
		t.Fatalf("expected one plugin trust warning, got: %+v", got.Warnings)
	}
}

func TestRunScanAppliesPolicyPluginPaths(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "policy-plugin.sh")
	script := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		"cat <<'EOF'\n" +
		`{"schemaVersion":"linux-nixer.scan.v1","items":[{"kind":"plugin-finding","name":"thing","path":"/opt/policy-plugin-thing","reason":"found by policy plugin"}]}` + "\n" +
		"EOF\n"
	if err := os.WriteFile(pluginPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(dir, "policy.json")
	policyJSON := `{"schemaVersion":"linux-nixer.policy.v1","plugins":["` + pluginPath + `"]}`
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "scan.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--policy", policyPath, "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	found := false
	for _, item := range got.Items {
		if item.Kind == "plugin-finding" && item.Path == "/opt/policy-plugin-thing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected policy-configured plugin item in scan output: %+v", got.Items)
	}
}

func TestRunScanPluginTimeoutFlag(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "slow-plugin.sh")
	script := "#!/bin/sh\n" +
		"cat >/dev/null\n" +
		"sleep 1\n" +
		"cat <<'EOF'\n" +
		`{"schemaVersion":"linux-nixer.scan.v1","items":[{"kind":"plugin-finding","name":"thing","path":"/opt/slow-plugin-thing","reason":"found by slow plugin"}]}` + "\n" +
		"EOF\n"
	if err := os.WriteFile(pluginPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "scan.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--plugin", pluginPath, "--plugin-timeout", "100ms", "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatalf("scan should succeed even when a plugin times out, got: %v", err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	for _, item := range got.Items {
		if item.Kind == "plugin-finding" {
			t.Fatalf("expected timed-out plugin to contribute no items, got: %+v", got.Items)
		}
	}
	foundWarning := false
	for _, w := range got.Warnings {
		if w.Source == "plugin:slow-plugin.sh" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("expected a warning from the timed-out plugin, got: %+v", got.Warnings)
	}
}

func TestRunScanResolvesBaselineIDFromProjectBaselines(t *testing.T) {
	project := t.TempDir()
	root := filepath.Join(project, "root")
	script := filepath.Join(root, "usr/local/bin/tool")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\necho same\n")
	if err := os.WriteFile(script, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	baselineDir := filepath.Join(project, "baselines")
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		t.Fatal(err)
	}
	baselineJSON := fmt.Sprintf(`{"files":[{"path":"/usr/local/bin/tool","type":"script","mode":"-rwxr-xr-x","size":%d,"sha256":"%x"}]}`, len(content), sum)
	if err := os.WriteFile(filepath.Join(baselineDir, "ubuntu-24.04.json"), []byte(baselineJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	outPath := filepath.Join(project, "scan.json")
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--include", "/usr/local/bin", "--baseline", "ubuntu:24.04", "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	for _, finding := range got.FilesystemDiff {
		if finding.Path == "/usr/local/bin/tool" {
			t.Fatalf("baseline-matched file should not be reported: %+v", got.FilesystemDiff)
		}
	}
}

func TestRunScanAppliesPolicy(t *testing.T) {
	project := t.TempDir()
	root := filepath.Join(project, "root")
	writeFile(t, root, "/usr/local/bin/tool", "#!/bin/sh\necho changed\n")
	if err := os.Chmod(filepath.Join(root, "usr/local/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	baselineDir := filepath.Join(project, "baselines")
	if err := os.MkdirAll(baselineDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baselineDir, "ubuntu-24.04.json"), []byte(`{"files":[{"path":"/usr/local/bin/tool","type":"script","mode":"-rwxr-xr-x","size":20,"sha256":"different"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(project, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","includePaths":["/usr/local/bin"],"baseline":"ubuntu:24.04","deep":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)

	outPath := filepath.Join(project, "scan.json")
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--policy", policyPath, "--out", outPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	found := false
	for _, finding := range got.FilesystemDiff {
		if finding.Path == "/usr/local/bin/tool" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy include/baseline should report changed file: %+v", got.FilesystemDiff)
	}
}

func TestRunReviewAppliesPolicy(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "reviewed.json")
	policyPath := filepath.Join(dir, "policy.json")
	writeScan(t, scanPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
			{Manager: "snap", Name: "hello", Source: "/snap/hello"},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/tmp/tool", Category: "script"},
		},
	})
	if err := os.WriteFile(policyPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","confirmManagers":["apt"],"excludePathPrefixes":["/tmp"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanPath, "--out", outPath, "--policy", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, outPath, &got)
	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("apt decision=%q, want confirmed", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("snap decision=%q, want candidate", got.Packages[1].Decision)
	}
	if got.FilesystemDiff[0].Decision != model.DecisionExcluded {
		t.Fatalf("filesystem decision=%q, want excluded", got.FilesystemDiff[0].Decision)
	}
}

func TestRunReviewExportThenImportDecisionsRoundTrips(t *testing.T) {
	dir := t.TempDir()
	scanAPath := filepath.Join(dir, "scan-a.json")
	reviewedAPath := filepath.Join(dir, "reviewed-a.json")
	decisionsPath := filepath.Join(dir, "decisions.json")
	scanBPath := filepath.Join(dir, "scan-b.json")
	reviewedBPath := filepath.Join(dir, "reviewed-b.json")

	writeScan(t, scanAPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Path: "/etc/systemd/system/app.service"},
		},
	})

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"review", "--scan", scanAPath, "--out", reviewedAPath, "--confirm-kind", "service", "--confirm-manager", "apt", "--export-decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote decisions:") {
		t.Fatalf("review stdout missing decisions path:\n%s", stdout.String())
	}

	// A second, freshly-generated scan of "the same host": same finding
	// identities, plus one brand-new finding never seen before.
	writeScan(t, scanBPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Version: "8.1"},
			{Manager: "apt", Name: "new-tool"},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Path: "/etc/systemd/system/app.service"},
		},
	})

	stdout.Reset()
	err = run(context.Background(), []string{"review", "--scan", scanBPath, "--out", reviewedBPath, "--import-decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got model.ScanReport
	readScan(t, reviewedBPath, &got)
	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("curl decision=%q, want confirmed (imported from A)", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("new-tool decision=%q, want candidate (no decision to import)", got.Packages[1].Decision)
	}
	if got.Services[0].Decision != model.DecisionConfirmed {
		t.Fatalf("service decision=%q, want confirmed (imported from A)", got.Services[0].Decision)
	}
}

func TestRunSummaryComparesDecisionsAcrossScans(t *testing.T) {
	dir := t.TempDir()
	scanAPath := filepath.Join(dir, "scan-a.json")
	reviewedAPath := filepath.Join(dir, "reviewed-a.json")
	decisionsPath := filepath.Join(dir, "decisions.json")
	scanBPath := filepath.Join(dir, "scan-b.json")
	reviewedBPath := filepath.Join(dir, "reviewed-b.json")

	writeScan(t, scanAPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Path: "/etc/systemd/system/app.service"},
		},
	})
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"review", "--scan", scanAPath, "--out", reviewedAPath, "--confirm-kind", "service", "--confirm-manager", "apt", "--export-decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}

	// Scan B, later: curl unchanged, service now excluded (changed), and a
	// new git source confirmed (newly decided). No import, so it's decided
	// independently of A, exercising the diff purely via --compare-decisions.
	writeScan(t, scanBPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "app.service", Path: "/etc/systemd/system/app.service", Decision: model.DecisionExcluded},
		},
		GitSources: []model.GitSource{
			{Path: "/home/alice/app", Decision: model.DecisionConfirmed},
		},
	})
	stdout.Reset()
	if err := run(context.Background(), []string{"review", "--scan", scanBPath, "--out", reviewedBPath, "--confirm-manager", "apt"}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	err := run(context.Background(), []string{"summary", "--scan", reviewedBPath, "--compare-decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{
		"## Migration progress since last snapshot",
		"previously decided: 2",
		"currently decided: 3",
		"newly decided: 1",
		"changed: 1",
		"git-source `/home/alice/app` -> confirmed",
		"service `systemd:app.service`: confirmed -> excluded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary output missing %q:\n%s", want, out)
		}
	}

	stdout.Reset()
	err = run(context.Background(), []string{"summary", "--scan", reviewedBPath, "--compare-decisions", decisionsPath, "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Total    int `json:"total"`
		Progress struct {
			PreviousDecided int `json:"previousDecided"`
			CurrentDecided  int `json:"currentDecided"`
		} `json:"progress"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("summary --json output not parseable: %v\n%s", err, stdout.String())
	}
	if decoded.Total == 0 {
		t.Fatalf("expected top-level summary fields alongside progress: %+v", decoded)
	}
	if decoded.Progress.PreviousDecided != 2 || decoded.Progress.CurrentDecided != 3 {
		t.Fatalf("unexpected progress in JSON output: %+v", decoded.Progress)
	}
}

func TestRunRescanImportsDecisionsAndWritesProgressSummary(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	writeFile(t, root, "/var/lib/dpkg/status", `Package: unknown-tool
Status: install ok installed
Version: 1.0
`)
	decisionsPath := filepath.Join(dir, "decisions.json")
	if err := os.WriteFile(decisionsPath, []byte(`{"schemaVersion":"linux-nixer.decisions.v1","entries":[{"domain":"package","key":"apt:unknown-tool","decision":"excluded"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "rescan")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"rescan", "--root", root, "--out", outDir, "--import-decisions", decisionsPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"scan.json", "reviewed.json", "summary.md"} {
		if _, err := os.Stat(filepath.Join(outDir, rel)); err != nil {
			t.Fatalf("rescan did not write %s: %v\nstdout:\n%s", rel, err, stdout.String())
		}
	}
	var reviewed model.ScanReport
	readScan(t, filepath.Join(outDir, "reviewed.json"), &reviewed)
	if len(reviewed.Packages) == 0 || reviewed.Packages[0].Name != "unknown-tool" || reviewed.Packages[0].Decision != model.DecisionExcluded {
		t.Fatalf("imported decision was not applied: %+v", reviewed.Packages)
	}
	summary, err := os.ReadFile(filepath.Join(outDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "## Migration progress since last snapshot") || !strings.Contains(string(summary), "previously decided: 1") {
		t.Fatalf("rescan summary missing progress:\n%s", summary)
	}
}

func TestRunCaptureWritesWorkflowArtifacts(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	out := filepath.Join(dir, "capture")
	writeFile(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

Package: unknown-tool
Status: install ok installed
Version: 1.0

`)
	writeFile(t, root, "/usr/local/bin/manual-tool", "#!/bin/sh\necho manual\n")
	if err := os.Chmod(filepath.Join(root, "usr/local/bin/manual-tool"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"capture", "--root", root, "--include", "/usr/local/bin", "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		filepath.Join(out, "scan.json"),
		filepath.Join(out, "reviewed.json"),
		filepath.Join(out, "summary.md"),
		filepath.Join(out, "nix-config", "flake.nix"),
		filepath.Join(out, "nix-config", "reports", "migration-checklist.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	for _, want := range []string{"wrote scan:", "wrote reviewed scan:", "wrote summary:", "wrote nix config:"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("capture stdout missing %q:\n%s", want, stdout.String())
		}
	}

	var reviewed model.ScanReport
	readScan(t, filepath.Join(out, "reviewed.json"), &reviewed)
	decisions := map[string]model.Decision{}
	for _, pkg := range reviewed.Packages {
		decisions[pkg.Name] = pkg.Decision
	}
	if decisions["curl"] != model.DecisionConfirmed {
		t.Fatalf("curl decision=%q, want confirmed in %+v", decisions["curl"], reviewed.Packages)
	}
	if decisions["unknown-tool"] != model.DecisionCandidate {
		t.Fatalf("unknown-tool decision=%q, want candidate in %+v", decisions["unknown-tool"], reviewed.Packages)
	}

	summary, err := os.ReadFile(filepath.Join(out, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "Pending findings:") {
		t.Fatalf("summary missing pending count:\n%s", string(summary))
	}

	stdout.Reset()
	err = run(context.Background(), []string{"validate", "--scan", filepath.Join(out, "reviewed.json")}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunCaptureAppliesPolicy(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	out := filepath.Join(dir, "capture")
	policyPath := filepath.Join(dir, "policy.json")
	writeFile(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

`)
	writeFile(t, root, "/custom/bin/tool", "#!/bin/sh\necho custom\n")
	if err := os.Chmod(filepath.Join(root, "custom/bin/tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1","autoSafe":false,"confirmManagers":["apt"],"includePaths":["/custom/bin"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"capture", "--root", root, "--policy", policyPath, "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var reviewed model.ScanReport
	readScan(t, filepath.Join(out, "reviewed.json"), &reviewed)
	if len(reviewed.Packages) != 1 || reviewed.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("policy confirmManagers not applied: %+v", reviewed.Packages)
	}
	found := false
	for _, finding := range reviewed.FilesystemDiff {
		if finding.Path == "/custom/bin/tool" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy includePaths not applied: %+v", reviewed.FilesystemDiff)
	}
}

func TestRunCaptureAppliesPreset(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	out := filepath.Join(dir, "capture")
	writeFile(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"capture", "--root", root, "--preset", "developer-machine", "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var reviewed model.ScanReport
	readScan(t, filepath.Join(out, "reviewed.json"), &reviewed)
	found := false
	for _, item := range reviewed.Items {
		if item.Path == "/home/alice/project/go.mod" {
			found = true
			if item.Decision != model.DecisionConfirmed {
				t.Fatalf("developer-machine preset should confirm dev-project findings: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("expected go.mod dev-project item: %+v", reviewed.Items)
	}
}

func TestRunScanRejectsPresetAndPolicyTogether(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"schemaVersion":"linux-nixer.policy.v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "scan.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--policy", policyPath, "--preset", "workstation", "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error when --policy and --preset are both given")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunScanRejectsUnknownPreset(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	out := filepath.Join(dir, "scan.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", "--root", root, "--preset", "bogus", "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), "unknown policy preset") || !strings.Contains(err.Error(), "workstation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunCapturePresetDefaultMatchesNoPreset(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")

	outNoFlag := filepath.Join(t.TempDir(), "capture-no-flag")
	outDefault := filepath.Join(t.TempDir(), "capture-default")

	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"capture", "--root", root, "--out", outNoFlag}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run(context.Background(), []string{"capture", "--root", root, "--preset", "default", "--out", outDefault}, strings.NewReader(""), &stdout, &stdout); err != nil {
		t.Fatal(err)
	}

	noFlagBytes, err := os.ReadFile(filepath.Join(outNoFlag, "reviewed.json"))
	if err != nil {
		t.Fatal(err)
	}
	defaultBytes, err := os.ReadFile(filepath.Join(outDefault, "reviewed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(noFlagBytes) != string(defaultBytes) {
		t.Fatalf("--preset default should produce identical output to omitting --preset entirely:\nno-flag: %s\ndefault: %s", noFlagBytes, defaultBytes)
	}
}

func TestRunCaptureFailOnPendingLeavesArtifacts(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	out := filepath.Join(dir, "capture")
	writeFile(t, root, "/var/lib/dpkg/status", `Package: unknown-tool
Status: install ok installed
Version: 1.0

`)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"capture", "--root", root, "--out", out, "--fail-on-pending"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected capture to fail on pending findings")
	}
	if !strings.Contains(err.Error(), "pending findings") {
		t.Fatalf("unexpected capture error: %v", err)
	}
	for _, path := range []string{
		filepath.Join(out, "scan.json"),
		filepath.Join(out, "reviewed.json"),
		filepath.Join(out, "summary.md"),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact after failed gate %s: %v", path, statErr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(out, "nix-config", "flake.nix")); !os.IsNotExist(statErr) {
		t.Fatalf("nix config should not be generated after failed pending gate, stat err=%v", statErr)
	}
}

func TestRunGenerateRejectsInvalidScan(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	out := filepath.Join(dir, "nix-config")
	writeScan(t, scanPath, model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true, Decision: model.DecisionConfirmed},
		},
	})

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"generate", "--scan", scanPath, "--out", out}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected generate to reject invalid scan")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("unexpected generate error: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("generate should not create output for invalid scan, stat err=%v", statErr)
	}
}

func TestRunSummaryWritesMarkdown(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Decision: model.DecisionConfirmed},
			{Manager: "apt", Name: "git", NixNames: []string{"git"}, Decision: model.DecisionCandidate},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"summary", "--scan", scanPath}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	got := stdout.String()
	for _, want := range []string{"# Review summary", "Total findings: 2", "Pending findings: 1", "## Review focus", "Nix candidate coverage gaps: 0 unmapped packages", "## Next actions", "system packages: 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
}

func TestRunSummaryWritesJSON(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Decision: model.DecisionConfirmed},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"summary", "--scan", scanPath, "--json"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Total               int `json:"total"`
		GeneratedCandidates int `json:"generatedCandidates"`
		NixImpact           struct {
			SystemPackages int `json:"systemPackages"`
		} `json:"nixImpact"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid json summary: %v\n%s", err, stdout.String())
	}
	if got.Total != 1 || got.NixImpact.SystemPackages != 1 || got.GeneratedCandidates != 1 {
		t.Fatalf("unexpected json summary: %+v", got)
	}
}

func TestRunSummaryFailOnPending(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "reviewed.json")
	report := model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Packages: []model.Package{
			{Manager: "apt", Name: "git", NixNames: []string{"git"}, Decision: model.DecisionCandidate},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Category: "stateful-data", Decision: model.DecisionMigrationNote},
		},
	}
	writeScan(t, scanPath, report)

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"summary", "--scan", scanPath, "--fail-on-pending"}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected pending summary to fail")
	}
	if !strings.Contains(err.Error(), "1 pending findings") {
		t.Fatalf("unexpected error: %v", err)
	}

	report.Packages[0].Decision = model.DecisionConfirmed
	writeScan(t, scanPath, report)
	stdout.Reset()
	err = run(context.Background(), []string{"summary", "--scan", scanPath, "--fail-on-pending"}, strings.NewReader(""), &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
}

func writeScan(t *testing.T, path string, report model.ScanReport) {
	t.Helper()
	writeJSONFile(t, path, report)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func readScan(t *testing.T, path string, report *model.ScanReport) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(report); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	target := filepath.Join(root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func countWarnings(warnings []model.Warning, source, text string) int {
	count := 0
	for _, warning := range warnings {
		if warning.Source == source && strings.Contains(warning.Message, text) {
			count++
		}
	}
	return count
}
