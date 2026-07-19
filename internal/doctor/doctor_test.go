package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectHostFromGeneratedFlake(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "flake.nix"), []byte(`{
  outputs = { self, nixpkgs, ... }: {
    nixosConfigurations.demo-host = nixpkgs.lib.nixosSystem { };
  };
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectHost(project); got != "demo-host" {
		t.Fatalf("host=%q, want demo-host", got)
	}
}

func TestCheckProjectFilesRequiresGeneratedFiles(t *testing.T) {
	project := t.TempDir()
	checks := CheckProjectFiles(project)
	if len(checks) == 0 {
		t.Fatal("expected checks")
	}
	for _, check := range checks {
		if check.OK {
			t.Fatalf("empty project should fail required file check: %+v", check)
		}
	}
}

func TestRunVMSuggestsBootScriptWhenBuildSucceeds(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")
	mkdirVMResult(t, "demo")

	result := Run(context.Background(), Options{
		Project: project,
		VM:      true,
		Host:    "demo",
		Runner:  successRunner,
	})

	assertCheck(t, result, "vm build:demo", true)
	assertCheck(t, result, "vm script:demo", true)
	if len(result.Suggestions) == 0 || !strings.Contains(result.Suggestions[0], "result/bin/run-demo-vm") {
		t.Fatalf("missing boot suggestion: %+v", result.Suggestions)
	}
}

func TestRunBootFailsWhenScriptMissing(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")

	result := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Runner:  successRunner,
	})

	assertCheck(t, result, "vm script:demo", false)
	if result.OK {
		t.Fatal("result should fail when boot script is missing")
	}
}

func TestRunBootUsesRunner(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")
	mkdirVMResult(t, "demo")
	var booted bool

	result := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Contains(name, "run-demo-vm") {
				booted = true
				return []byte("boot ok"), nil
			}
			return []byte("ok"), nil
		},
	})

	if !booted {
		t.Fatal("boot runner was not called")
	}
	assertCheck(t, result, "vm boot:demo", true)
}

func TestRunBootFailureAndTimeout(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")
	mkdirVMResult(t, "demo")

	failed := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Contains(name, "run-demo-vm") {
				return []byte("boom"), errors.New("failed")
			}
			return []byte("ok"), nil
		},
	})
	assertCheck(t, failed, "vm boot:demo", false)

	timeout := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Timeout: time.Nanosecond,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Contains(name, "run-demo-vm") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []byte("ok"), nil
		},
	})
	assertCheck(t, timeout, "vm boot:demo", true)
}

func writeGeneratedProject(t *testing.T, host string) string {
	t.Helper()
	project := t.TempDir()
	files := []string{
		"hosts/generated/configuration.nix",
		"users/home.nix",
		"modules/containers.nix",
		"reports/package-sources.md",
		"reports/filesystem.md",
		"reports/users.md",
		"reports/containers.md",
		"reports/git-sources.md",
		"reports/languages.md",
		"reports/migration-report.md",
		"reports/migration-checklist.md",
		"reports/system-config.md",
		"reports/devops-config.md",
		"reports/backup-sync.md",
	}
	for _, rel := range files {
		path := filepath.Join(project, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	flake := `{
  outputs = { self, nixpkgs, ... }: {
    nixosConfigurations.` + host + ` = nixpkgs.lib.nixosSystem { };
  };
}`
	if err := os.WriteFile(filepath.Join(project, "flake.nix"), []byte(flake), 0o644); err != nil {
		t.Fatal(err)
	}
	return project
}

func mkdirVMResult(t *testing.T, host string) {
	t.Helper()
	path := filepath.Join("result", "bin", "run-"+host+"-vm")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func successRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte("ok"), nil
}

func assertCheck(t *testing.T, result Result, name string, ok bool) {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			if check.OK != ok {
				t.Fatalf("check %s OK=%v, want %v: %+v", name, check.OK, ok, result.Checks)
			}
			return
		}
	}
	t.Fatalf("check %s missing from %+v", name, result.Checks)
}
