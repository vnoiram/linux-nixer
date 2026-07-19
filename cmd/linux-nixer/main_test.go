package main

import (
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
	for _, want := range []string{"# Review summary", "Total findings: 2", "Pending findings: 1", "system packages: 1"} {
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
		Total     int `json:"total"`
		NixImpact struct {
			SystemPackages int `json:"systemPackages"`
		} `json:"nixImpact"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid json summary: %v\n%s", err, stdout.String())
	}
	if got.Total != 1 || got.NixImpact.SystemPackages != 1 {
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
