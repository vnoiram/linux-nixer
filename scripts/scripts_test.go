package scripts_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReleaseProvenanceScript(t *testing.T) {
	cmd := exec.Command("bash", "scripts/write-release-provenance.sh", "v1.2.3", "abc123", "2026-07-25T00:00:00Z", "go version go1.22 linux/amd64")
	cmd.Dir = ".."
	cmd.Stdin = strings.NewReader("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  linux-nixer-v1.2.3-linux-amd64.tar.gz\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("write-release-provenance failed: %v\n%s", err, out)
	}
	var got struct {
		SchemaVersion string `json:"schemaVersion"`
		Tag           string `json:"tag"`
		Commit        string `json:"commit"`
		BuiltAt       string `json:"builtAt"`
		GoVersion     string `json:"goVersion"`
		Platforms     []string
		Artifacts     []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid provenance JSON: %v\n%s", err, out)
	}
	if got.SchemaVersion != "linux-nixer.release-provenance.v1" || got.Tag != "v1.2.3" || got.Commit != "abc123" || got.BuiltAt == "" || got.GoVersion == "" {
		t.Fatalf("unexpected provenance metadata: %+v", got)
	}
	if len(got.Platforms) != 2 || len(got.Artifacts) != 1 || got.Artifacts[0].Name == "" || got.Artifacts[0].SHA256 == "" {
		t.Fatalf("unexpected provenance artifacts/platforms: %+v", got)
	}
}

func TestCITimingReportScript(t *testing.T) {
	cmd := exec.Command("bash", "scripts/ci-timing-report.sh")
	cmd.Dir = ".."
	cmd.Stdin = strings.NewReader("test\t2.5\nnix-verify\t7\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ci-timing-report failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{"# CI timing report", "| test | 2.500 |", "| nix-verify | 7.000 |", "- total seconds: 9.500", "- slowest step: nix-verify"} {
		if !strings.Contains(got, want) {
			t.Fatalf("timing report missing %q:\n%s", want, got)
		}
	}
}

func TestTimedStepScript(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "timing.tsv")
	cmd := exec.Command("bash", "scripts/timed-step.sh", "sample", outPath, "--", "bash", "-lc", "true")
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("timed-step failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "sample\t") {
		t.Fatalf("unexpected timing row: %q", got)
	}
}
