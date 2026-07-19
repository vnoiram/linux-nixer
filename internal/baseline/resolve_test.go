package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDirectPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(`{"files":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Resolve(path, dir)
	if !got.OK || got.Path != path || got.Source != "direct-path" {
		t.Fatalf("Resolve direct=%+v", got)
	}
}

func TestResolveBaselineIDFromProjectBaselines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baselines", "ubuntu-24.04.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"files":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Resolve("ubuntu:24.04", dir)
	if !got.OK || got.Path != path || got.Source != "project-baselines" {
		t.Fatalf("Resolve id=%+v", got)
	}
}

func TestResolveBaselineIDFromUserCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	t.Setenv("XDG_CACHE_HOME", cache)
	path := filepath.Join(cache, "linux-nixer", "baselines", "debian-12.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"files":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Resolve("debian:12", dir)
	if !got.OK || got.Path != path || got.Source != "user-cache" {
		t.Fatalf("Resolve cache id=%+v", got)
	}
}

func TestNormalizeID(t *testing.T) {
	got, ok := NormalizeID("ubuntu:24.04")
	if !ok || got != "ubuntu-24.04.json" {
		t.Fatalf("NormalizeID ubuntu=%q %v", got, ok)
	}
	if got, ok := NormalizeID("ubuntu/evil:24.04"); ok || got != "" {
		t.Fatalf("NormalizeID invalid=%q %v", got, ok)
	}
}
