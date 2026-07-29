package doctor

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// bootFailureSignatures are low-false-positive markers of a hung or
// crashed Linux boot. Checked against captured VM console output
// regardless of how the boot script exited (timeout, error, or a clean
// exit that still shows a failure) — a positive success string isn't
// checked instead, since it would vary across NixOS versions/configs and
// risk false negatives.
var bootFailureSignatures = []string{
	"kernel panic",
	"you are in emergency mode",
	"give root password for maintenance",
	"unable to mount root fs",
	"no working init found",
	"segmentation fault",
}

// bootFailureSignature returns the first bootFailureSignatures entry found
// in output (case-insensitive), or "" if none match.
func bootFailureSignature(output string) string {
	lower := strings.ToLower(output)
	for _, sig := range bootFailureSignatures {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

type Result struct {
	Project         string          `json:"project"`
	OK              bool            `json:"ok"`
	Checks          []Check         `json:"checks"`
	ProjectFileDiff ProjectFileDiff `json:"projectFileDiff"`
	Suggestions     []string        `json:"suggestions,omitempty"`
}

type Options struct {
	Project       string
	VM            bool
	Boot          bool
	BootReadiness bool
	Host          string
	Timeout       time.Duration
	Runner        Runner
}

type Runner func(context.Context, string, ...string) ([]byte, error)

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

type ProjectFileDiff struct {
	Expected []string `json:"expected"`
	Missing  []string `json:"missing,omitempty"`
	Stale    []string `json:"stale,omitempty"`
	Extra    []string `json:"extra,omitempty"`
}

var expectedProjectFiles = []string{
	"flake.nix",
	"hosts/generated/configuration.nix",
	"users/home.nix",
	"modules/containers.nix",
	"modules/services.nix",
	"modules/filesystem-findings.nix",
	"reports/package-sources.md",
	"reports/filesystem.md",
	"reports/users.md",
	"reports/containers.md",
	"reports/git-sources.md",
	"reports/languages.md",
	"reports/index.md",
	"reports/migration-dashboard.md",
	"reports/unmapped-packages.md",
	"reports/service-render-eligibility.md",
	"reports/baseline-provenance.md",
	"reports/dev-projects.md",
	"reports/user-config.md",
	"reports/desktop.md",
	"reports/migration-report.md",
	"reports/migration-checklist.md",
	"reports/migration-annotations.nix",
	"reports/system-config.md",
	"reports/devops-config.md",
	"reports/backup-sync.md",
	"reports/hardware.md",
}

var expectedSingleModuleProjectFiles = []string{
	"flake.nix",
	"hosts/generated/configuration.nix",
	"users/home.nix",
	"modules/migration.nix",
	"reports/package-sources.md",
	"reports/filesystem.md",
	"reports/users.md",
	"reports/containers.md",
	"reports/git-sources.md",
	"reports/languages.md",
	"reports/index.md",
	"reports/migration-dashboard.md",
	"reports/unmapped-packages.md",
	"reports/service-render-eligibility.md",
	"reports/baseline-provenance.md",
	"reports/dev-projects.md",
	"reports/user-config.md",
	"reports/desktop.md",
	"reports/migration-report.md",
	"reports/migration-checklist.md",
	"reports/migration-annotations.nix",
	"reports/system-config.md",
	"reports/devops-config.md",
	"reports/backup-sync.md",
	"reports/hardware.md",
}

func expectedFilesForProject(project string) []string {
	if _, err := os.Stat(filepath.Join(project, "modules/migration.nix")); err == nil {
		return expectedSingleModuleProjectFiles
	}
	return expectedProjectFiles
}

func CheckProjectFiles(project string) []Check {
	var checks []Check
	for _, rel := range expectedFilesForProject(project) {
		_, err := os.Stat(filepath.Join(project, rel))
		checks = append(checks, Check{Name: "file:" + rel, OK: err == nil, Message: errorMessage(err)})
	}
	return checks
}

func CheckProjectFileDiff(project string) ProjectFileDiff {
	expectedFiles := expectedFilesForProject(project)
	diff := ProjectFileDiff{Expected: append([]string{}, expectedFiles...)}
	expected := map[string]bool{}
	for _, rel := range expectedFiles {
		expected[rel] = true
		if _, err := os.Stat(filepath.Join(project, rel)); err != nil {
			diff.Missing = append(diff.Missing, rel)
		}
	}
	filepath.WalkDir(project, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(project, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !expected[rel] {
			if staleGeneratedProjectFile(rel) {
				diff.Stale = append(diff.Stale, rel)
			} else {
				diff.Extra = append(diff.Extra, rel)
			}
		}
		return nil
	})
	sort.Strings(diff.Stale)
	sort.Strings(diff.Extra)
	return diff
}

func staleGeneratedProjectFile(rel string) bool {
	switch {
	case strings.HasPrefix(rel, "reports/"):
		return true
	case strings.HasPrefix(rel, "modules/") && strings.HasSuffix(rel, ".nix"):
		return true
	default:
		return false
	}
}

func Run(ctx context.Context, opts Options) Result {
	if opts.Boot {
		opts.VM = true
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	runner := opts.Runner
	if runner == nil {
		runner = defaultRunner
	}
	result := Result{Project: opts.Project, OK: true}
	result.ProjectFileDiff = CheckProjectFileDiff(opts.Project)
	result.Checks = append(result.Checks, CheckProjectFiles(opts.Project)...)
	for _, c := range result.Checks {
		if !c.OK {
			result.OK = false
		}
	}
	if opts.Runner == nil {
		if _, err := exec.LookPath("nix"); err != nil {
			result.Checks = append(result.Checks, Check{Name: "nix", OK: false, Message: "nix command not found; skipping flake validation"})
			result.Suggestions = append(result.Suggestions, "Install Nix to run nix flake check and VM validation.")
			result.OK = false
			return result
		}
	}
	flakeRef, cleanup, err := nixSafeFlakeRef(opts.Project)
	if err != nil {
		result.Checks = append(result.Checks, Check{Name: "nix flake copy", OK: false, Message: err.Error()})
		result.OK = false
		return result
	}
	defer cleanup()
	if out, err := runner(ctx, "nix", "flake", "check", flakeRef); err != nil {
		if opts.VM && nixFlakeCheckBootabilityAssertions(string(out)) {
			result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: true, Message: "full NixOS flake check hit bootability assertions for migration scaffolding; continuing with VM derivation build"})
		} else {
			result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: false, Message: diagnosticMessage(string(out))})
			result.OK = false
		}
	} else {
		result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: true})
	}
	if opts.BootReadiness {
		host := opts.Host
		if host == "" {
			host = detectHost(opts.Project)
		}
		if host == "" {
			result.Checks = append(result.Checks, Check{Name: "vm boot readiness", OK: false, Message: "could not detect host; pass --host"})
			result.OK = false
		} else {
			script := vmScriptPath("result", host)
			message := "host=" + host + " timeout=" + opts.Timeout.String() + " script=" + script + " command=" + script + "; readiness only, VM was not started"
			result.Checks = append(result.Checks, Check{Name: "vm boot readiness:" + host, OK: true, Message: message})
			result.Suggestions = append(result.Suggestions, "Before running `doctor --boot`, expect a VM build, local qemu/KVM acceleration availability differences, and a timeout-based smoke check rather than a full login validation.")
		}
	}
	if opts.VM {
		host := opts.Host
		if host == "" {
			host = detectHost(opts.Project)
		}
		if host == "" {
			result.Checks = append(result.Checks, Check{Name: "vm", OK: false, Message: "could not detect host; pass --host"})
			result.OK = false
		} else {
			vmOutput, vmCleanup, err := tempVMOutputPath()
			if err != nil {
				result.Checks = append(result.Checks, Check{Name: "vm output", OK: false, Message: err.Error()})
				result.OK = false
				return result
			}
			defer vmCleanup()
			attr := flakeRef + "#nixosConfigurations." + host + ".config.system.build.vm"
			if out, err := runner(ctx, "nix", "build", "-o", vmOutput, attr); err != nil {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: false, Message: diagnosticMessage(string(out))})
				result.OK = false
			} else {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: true})
				script := vmScriptPath(vmOutput, host)
				if _, err := os.Stat(script); err != nil {
					result.Checks = append(result.Checks, Check{Name: "vm script:" + host, OK: false, Message: err.Error()})
					result.OK = false
				} else {
					result.Checks = append(result.Checks, Check{Name: "vm script:" + host, OK: true, Message: script})
					if opts.Boot {
						bootCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
						out, err := runner(bootCtx, script)
						cancel()
						if sig := bootFailureSignature(string(out)); sig != "" {
							result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: false, Message: "boot output contains a failure signature (" + sig + "): " + string(out)})
							result.OK = false
						} else if err != nil {
							if bootCtx.Err() == context.DeadlineExceeded {
								result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: true, Message: "VM process started, reached timeout, and its output showed no known boot-failure signature"})
							} else {
								result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: false, Message: string(out)})
								result.OK = false
							}
						} else {
							result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: true, Message: string(out)})
						}
					} else {
						result.Suggestions = append(result.Suggestions, "Run "+script+" to boot the generated VM after reviewing secrets and migration notes.")
					}
				}
			}
		}
	}
	return result
}

func tempVMOutputPath() (string, func(), error) {
	tmp, err := os.MkdirTemp("", "linux-nixer-doctor-vm-*")
	if err != nil {
		return "", func() {}, err
	}
	return filepath.Join(tmp, "result"), func() {
		_ = os.RemoveAll(tmp)
	}, nil
}

func nixSafeFlakeRef(project string) (string, func(), error) {
	tmp, err := os.MkdirTemp("", "linux-nixer-doctor-flake-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		_ = os.RemoveAll(tmp)
	}
	dst := filepath.Join(tmp, "nix-config")
	if err := copyTree(project, dst); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dst, cleanup, nil
}

func copyTree(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("copy generated flake: stat %s: %w", src, err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("copy generated flake: %s is not a directory", src)
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if info.Mode()&os.ModeType != 0 {
			return fmt.Errorf("copy generated flake: unsupported non-regular file %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func nixFlakeCheckBootabilityAssertions(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "failed assertions") &&
		strings.Contains(lower, "filesystems") &&
		strings.Contains(lower, "root file system") &&
		strings.Contains(lower, "boot.loader.grub.devices")
}

func diagnosticMessage(output string) string {
	if hint := diagnoseNixOutput(output); hint != "" {
		return hint + "\n\nRaw output:\n" + output
	}
	return output
}

func diagnoseNixOutput(output string) string {
	lower := strings.ToLower(output)
	location := nixDiagnosticLocation(output)
	withLocation := func(message string) string {
		if location == "" {
			return message
		}
		return message + " Location: " + location + "."
	}
	switch {
	case strings.Contains(lower, "syntax error"):
		return withLocation("diagnostic: Nix syntax error; inspect the generated .nix file and the line/column in the raw output.")
	case strings.Contains(lower, "attribute") && strings.Contains(lower, "missing"):
		return withLocation("diagnostic: missing Nix attribute; check package names, host attribute names, or referenced flake outputs.")
	case strings.Contains(lower, "undefined variable"):
		return withLocation("diagnostic: undefined Nix variable; check generated references to packages, module arguments, or local bindings.")
	case strings.Contains(lower, "unknown option") || strings.Contains(lower, "the option") && strings.Contains(lower, "does not exist"):
		return withLocation("diagnostic: unknown NixOS option; check whether the generated option exists for the selected nixpkgs release.")
	case strings.Contains(lower, "dirty") || strings.Contains(lower, "flake.lock") || strings.Contains(lower, "cannot fetch"):
		return withLocation("diagnostic: flake input or lock issue; check flake.lock, network access, and dirty working tree warnings.")
	case strings.Contains(lower, "while evaluating") || strings.Contains(lower, "evaluation error"):
		return withLocation("diagnostic: Nix evaluation failed; use the raw output to find the option or expression that triggered evaluation.")
	default:
		return ""
	}
}

func nixDiagnosticLocation(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if loc := locationAfter(line, " at "); loc != "" {
			return loc
		}
		if loc := locationAfter(line, " at «"); loc != "" {
			return strings.TrimSuffix(loc, "»")
		}
		if strings.HasPrefix(line, "at ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "at "))
		}
	}
	return ""
}

func locationAfter(line, marker string) string {
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	loc := strings.TrimSpace(line[idx+len(marker):])
	if loc == "" || !strings.Contains(loc, ":") {
		return ""
	}
	return loc
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Run in its own process group so a timeout (in practice, --boot's VM
	// script) kills any subprocess it spawned too, not just its own
	// top-level process — mirroring internal/scanner/plugin.go's identical
	// hardening. Without this, a VM script that doesn't exec into qemu as
	// its last act would leave qemu running, reparented to init, after
	// only the script's top-level process gets killed on timeout; Wait
	// would then block on that orphan's inherited output pipe instead of
	// returning once the timeout fires.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

func vmScriptPath(resultPath, host string) string {
	return filepath.Join(resultPath, "bin", "run-"+host+"-vm")
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func detectHost(project string) string {
	flake, err := os.ReadFile(filepath.Join(project, "flake.nix"))
	if err != nil {
		return ""
	}
	text := string(flake)
	marker := "nixosConfigurations."
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	rest := text[idx+len(marker):]
	var host []rune
	for _, r := range rest {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			host = append(host, r)
			continue
		}
		break
	}
	return string(host)
}
