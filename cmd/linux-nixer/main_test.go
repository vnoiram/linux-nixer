package main

import (
	"bytes"
	"context"
	"encoding/json"
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
