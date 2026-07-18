package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestAptScannerParsesInstalledPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

Package: removed
Status: deinstall ok config-files
Version: 1.0
`)

	report := &model.ScanReport{}
	if err := (AptScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Packages) != 1 {
		t.Fatalf("packages=%d, want 1", len(report.Packages))
	}
	if report.Packages[0].Name != "curl" || report.Packages[0].NixNames[0] != "curl" {
		t.Fatalf("unexpected package: %+v", report.Packages[0])
	}
}

func TestFilesystemDiffClassifiesSeededRandomLikeApps(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/random-seed-42/tools/fake-elf", append([]byte{0x7f, 'E', 'L', 'F'}, []byte("payload")...), 0o755)
	writeMode(t, root, "/random-seed-42/tools/script.py", []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o755)
	write(t, root, "/random-seed-42/app.desktop", "[Desktop Entry]\nName=Seeded\n")
	write(t, root, "/random-seed-42/seeded.service", "[Service]\nExecStart=/random-seed-42/tools/fake-elf\n")

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/random-seed-42"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]bool{}
	for _, finding := range report.FilesystemDiff {
		cats[finding.Category] = true
	}
	for _, want := range []string{"executable", "script", "desktop-entry", "service"} {
		if !cats[want] {
			t.Fatalf("missing category %q in %+v", want, report.FilesystemDiff)
		}
	}
}

func TestConfigScannerMarksSecretRiskDevOpsConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "users:\n- token: super-secret\n")
	report := &model.ScanReport{}
	if err := (ConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) == 0 {
		t.Fatal("expected config item")
	}
	if report.Items[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("decision=%q, want migration-note", report.Items[0].Decision)
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0].Message, "secret-risk") {
		t.Fatalf("expected secret warning, got %+v", report.Warnings)
	}
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	writeMode(t, root, path, []byte(content), 0o644)
}

func writeMode(t *testing.T, root, path string, content []byte, mode os.FileMode) {
	t.Helper()
	abs := filepath.Join(root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, content, mode); err != nil {
		t.Fatal(err)
	}
}
