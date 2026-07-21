package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
				"Policy include/exclude/plugin lists are merged",
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
			name: "review help",
			args: []string{"review", "-h"},
			wants: []string{
				"linux-nixer review",
				"c/k/t/m/x/s/n/q",
				"--pending-only",
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
			},
		},
		{
			name: "doctor help",
			args: []string{"doctor", "--help"},
			wants: []string{
				"linux-nixer doctor",
				"--vm",
				"--boot",
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

func TestRunPolicyInitRejectsUnknownPreset(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bogus-policy.json")

	var stdout bytes.Buffer
	err := run(context.Background(), []string{"policy", "init", "--preset", "bogus", "--out", policyPath}, strings.NewReader(""), &stdout, &stdout)
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), "unknown policy preset") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(policyPath); !os.IsNotExist(statErr) {
		t.Fatalf("policy file should not be written for unknown preset, stat err=%v", statErr)
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
	if !strings.Contains(err.Error(), "baseline create") || !strings.Contains(err.Error(), "baseline fetch") || !strings.Contains(err.Error(), "baseline import") {
		t.Fatalf("error should mention all three subcommands: %v", err)
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
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(report); err != nil {
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
