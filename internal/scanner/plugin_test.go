package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestPluginScannerMergesItemsAndWarnings(t *testing.T) {
	report := &model.ScanReport{
		Packages: []model.Package{{Manager: "apt", Name: "curl"}},
	}
	p := PluginScanner{
		Path: "/usr/local/bin/my-plugin",
		Runner: func(ctx context.Context, path string, req PluginRequest) (model.ScanReport, error) {
			return model.ScanReport{
				Packages: []model.Package{{Manager: "apt", Name: "should-not-merge"}},
				Items:    []model.Item{{Kind: "custom-finding", Path: "/opt/plugin-thing", Reason: "found by plugin"}},
				Warnings: []model.Warning{{Source: "my-plugin", Message: "heads up"}},
			}, nil
		},
	}

	if err := p.Scan(context.Background(), Options{Root: "/"}, report); err != nil {
		t.Fatal(err)
	}

	if len(report.Packages) != 1 {
		t.Fatalf("packages should not be merged from plugin output: %+v", report.Packages)
	}
	if len(report.Items) != 1 || report.Items[0].Kind != "custom-finding" {
		t.Fatalf("expected plugin item to be merged: %+v", report.Items)
	}
	if len(report.Warnings) != 1 || report.Warnings[0].Message != "heads up" {
		t.Fatalf("expected plugin warning to be merged: %+v", report.Warnings)
	}
}

func TestPluginScannerPassesRequestFields(t *testing.T) {
	var got PluginRequest
	p := PluginScanner{
		Path: "/plugins/example",
		Runner: func(ctx context.Context, path string, req PluginRequest) (model.ScanReport, error) {
			got = req
			return model.ScanReport{}, nil
		},
	}
	opts := Options{Root: "/mnt/rootfs", Deep: true, UseSudo: true, Includes: []string{"/opt"}, Excludes: []string{"/tmp"}}
	if err := p.Scan(context.Background(), opts, &model.ScanReport{}); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != PluginRequestSchemaVersion {
		t.Fatalf("schemaVersion=%q, want %q", got.SchemaVersion, PluginRequestSchemaVersion)
	}
	if got.Root != "/mnt/rootfs" || !got.Deep || !got.Sudo {
		t.Fatalf("unexpected request: %+v", got)
	}
	if len(got.Includes) != 1 || got.Includes[0] != "/opt" || len(got.Excludes) != 1 || got.Excludes[0] != "/tmp" {
		t.Fatalf("unexpected includes/excludes: %+v", got)
	}
}

func TestRunPluginProcessKillsWholeProcessGroupOnTimeout(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "slow-plugin.sh")
	// Forks a subprocess (sleep) that inherits the stdout pipe before the
	// top-level shell exits. If only the top-level process is killed on
	// timeout, the orphaned sleep keeps the pipe open and Wait blocks
	// until it exits on its own, defeating the timeout.
	script := "#!/bin/sh\nsleep 2 &\nwait\n"
	if err := os.WriteFile(pluginPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := runPluginProcess(ctx, pluginPath, PluginRequest{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > time.Second {
		t.Fatalf("runPluginProcess took %s to return after a 100ms timeout; the orphaned subprocess likely kept the output pipe open", elapsed)
	}
}

func TestPluginScannerWrapsRunnerError(t *testing.T) {
	p := PluginScanner{
		Path: "/plugins/broken",
		Runner: func(ctx context.Context, path string, req PluginRequest) (model.ScanReport, error) {
			return model.ScanReport{}, errors.New("boom")
		},
	}
	err := p.Scan(context.Background(), Options{Root: "/"}, &model.ScanReport{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "/plugins/broken") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error should name the plugin path and wrap the cause: %v", err)
	}
}
