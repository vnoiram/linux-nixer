package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vnoiram/linux-nixer/internal/model"
	"github.com/vnoiram/linux-nixer/internal/render"
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

func TestCheckProjectFilesCoversEveryRenderedFile(t *testing.T) {
	dir := t.TempDir()
	if err := render.Project(dir, model.ScanReport{}); err != nil {
		t.Fatal(err)
	}

	checks := CheckProjectFiles(dir)
	checked := map[string]bool{}
	for _, check := range checks {
		rel := strings.TrimPrefix(check.Name, "file:")
		checked[rel] = true
		if !check.OK {
			t.Fatalf("check %+v should pass against a real render.Project output", check)
		}
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if !checked[rel] {
			t.Errorf("render.Project wrote %q but CheckProjectFiles does not check it", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckProjectFileDiffReportsMissingAndExtraFiles(t *testing.T) {
	dir := t.TempDir()
	if err := render.Project(dir, model.ScanReport{}); err != nil {
		t.Fatal(err)
	}

	diff := CheckProjectFileDiff(dir)
	if len(diff.Missing) != 0 {
		t.Fatalf("rendered project should have no missing files: %+v", diff)
	}
	if len(diff.Expected) == 0 {
		t.Fatalf("expected file list should be populated: %+v", diff)
	}

	missingRel := "reports/users.md"
	if err := os.Remove(filepath.Join(dir, missingRel)); err != nil {
		t.Fatal(err)
	}
	extraRel := "reports/old-report.md"
	if err := os.WriteFile(filepath.Join(dir, extraRel), []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	diff = CheckProjectFileDiff(dir)
	if !slicesContain(diff.Missing, missingRel) {
		t.Fatalf("missing file diff did not include %q: %+v", missingRel, diff)
	}
	if !slicesContain(diff.Extra, extraRel) {
		t.Fatalf("extra file diff did not include %q: %+v", extraRel, diff)
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

func TestRunBootReadinessDoesNotBuildOrStartVM(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")
	var called []string

	result := Run(context.Background(), Options{
		Project:       project,
		BootReadiness: true,
		Host:          "demo",
		Timeout:       20 * time.Second,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = append(called, name+" "+strings.Join(args, " "))
			if name == "nix" && len(args) > 0 && args[0] == "build" {
				t.Fatalf("boot readiness should not build VM: %s %v", name, args)
			}
			if strings.Contains(name, "run-demo-vm") {
				t.Fatalf("boot readiness should not start VM: %s", name)
			}
			return []byte("ok"), nil
		},
	})

	assertCheck(t, result, "vm boot readiness:demo", true)
	check := findCheck(t, result, "vm boot readiness:demo")
	for _, want := range []string{"host=demo", "timeout=20s", "result/bin/run-demo-vm", "VM was not started"} {
		if !strings.Contains(check.Message, want) {
			t.Fatalf("readiness message missing %q: %+v", want, check)
		}
	}
	if len(called) != 1 || !strings.Contains(called[0], "nix flake check") {
		t.Fatalf("unexpected runner calls: %v", called)
	}
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

func TestRunBootDetectsFailureSignatureDespiteTimeoutOrCleanExit(t *testing.T) {
	t.Chdir(t.TempDir())
	project := writeGeneratedProject(t, "demo")
	mkdirVMResult(t, "demo")

	timeoutButPanicked := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Timeout: time.Nanosecond,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Contains(name, "run-demo-vm") {
				<-ctx.Done()
				return []byte("Kernel panic - not syncing: Attempted to kill init!"), ctx.Err()
			}
			return []byte("ok"), nil
		},
	})
	assertCheck(t, timeoutButPanicked, "vm boot:demo", false)
	if timeoutButPanicked.OK {
		t.Fatal("result should fail when boot output contains a kernel panic, even on timeout")
	}

	cleanExitButEmergency := Run(context.Background(), Options{
		Project: project,
		Boot:    true,
		Host:    "demo",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if strings.Contains(name, "run-demo-vm") {
				return []byte("You are in emergency mode."), nil
			}
			return []byte("ok"), nil
		},
	})
	assertCheck(t, cleanExitButEmergency, "vm boot:demo", false)
	if cleanExitButEmergency.OK {
		t.Fatal("result should fail when boot output shows emergency mode, even without a runner error")
	}
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
		"reports/hardware.md",
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
	check := findCheck(t, result, name)
	if check.OK != ok {
		t.Fatalf("check %s OK=%v, want %v: %+v", name, check.OK, ok, result.Checks)
	}
}

func findCheck(t *testing.T, result Result, name string) Check {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %s missing from %+v", name, result.Checks)
	return Check{}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDefaultRunnerKillsWholeProcessGroupOnTimeout(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "slow-vm-script.sh")
	// Forks a subprocess (sleep) that inherits the output pipe before the
	// top-level shell exits, mirroring a generated VM script that doesn't
	// exec into qemu as its last act. If only the top-level process is
	// killed on timeout, the orphaned sleep keeps the pipe open and Wait
	// blocks until it exits on its own, defeating the timeout.
	script := "#!/bin/sh\nsleep 2 &\nwait\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := defaultRunner(ctx, scriptPath)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > time.Second {
		t.Fatalf("defaultRunner took %s to return after a 100ms timeout; the orphaned subprocess likely kept the output pipe open", elapsed)
	}
}
