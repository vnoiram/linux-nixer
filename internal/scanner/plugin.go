package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vnoiram/linux-nixer/internal/model"
)

const PluginRequestSchemaVersion = "linux-nixer.plugin-request.v1"

// PluginRequest is written to a plugin's stdin as JSON when it is invoked
// as `<path> scan`.
type PluginRequest struct {
	SchemaVersion string   `json:"schemaVersion"`
	Root          string   `json:"root"`
	Deep          bool     `json:"deep"`
	Sudo          bool     `json:"sudo"` // informational only; the plugin process itself is never elevated
	Includes      []string `json:"includes,omitempty"`
	Excludes      []string `json:"excludes,omitempty"`
}

// PluginRunner executes a plugin and returns its parsed result. Injectable
// for hermetic tests, matching this package's existing CommandRunner
// pattern (Options.Runner) used throughout for the same reason.
type PluginRunner func(ctx context.Context, path string, req PluginRequest) (model.ScanReport, error)

// PluginScanner runs an external executable as a scanner. The plugin
// receives a PluginRequest as JSON on stdin and must write a
// model.ScanReport as JSON to stdout; only Items and Warnings are merged
// into the main report (see mergePluginReport) — a plugin can express
// arbitrary findings via model.Item without needing to know this tool's
// per-domain Nix-mapping/decision conventions for packages, services, etc.
//
// Plugins always run as the current user with no sudo elevation,
// regardless of --sudo — they are arbitrary code the user explicitly
// pointed this tool at (via --plugin PATH), and get no more trust than
// that. Execution is bounded by Timeout (default 30s) so one broken
// plugin can't hang a whole scan.
type PluginScanner struct {
	Path    string
	Timeout time.Duration
	Runner  PluginRunner
}

func (p PluginScanner) Name() string {
	return "plugin:" + filepath.Base(p.Path)
}

func (p PluginScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := PluginRequest{
		SchemaVersion: PluginRequestSchemaVersion,
		Root:          opts.Root,
		Deep:          opts.Deep,
		Sudo:          opts.UseSudo,
		Includes:      opts.Includes,
		Excludes:      opts.Excludes,
	}
	runner := p.Runner
	if runner == nil {
		runner = runPluginProcess
	}
	pluginReport, err := runner(runCtx, p.Path, req)
	if err != nil {
		return fmt.Errorf("plugin %s: %w", p.Path, err)
	}
	mergePluginReport(report, pluginReport)
	return nil
}

// CheckPlugin invokes path once with a synthetic request (root "/", no
// deep/sudo/includes/excludes) and returns its parsed report, without
// merging into any real scan. It's the entry point for a standalone
// protocol check (`plugin check`) that lets a plugin author validate their
// executable before pointing a real `scan`/`capture` at it.
func CheckPlugin(ctx context.Context, path string, timeout time.Duration) (model.ScanReport, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := PluginRequest{SchemaVersion: PluginRequestSchemaVersion, Root: "/"}
	return runPluginProcess(runCtx, path, req)
}

func mergePluginReport(dst *model.ScanReport, src model.ScanReport) {
	dst.Items = append(dst.Items, src.Items...)
	dst.Warnings = append(dst.Warnings, src.Warnings...)
}

func runPluginProcess(ctx context.Context, path string, req PluginRequest) (model.ScanReport, error) {
	input, err := json.Marshal(req)
	if err != nil {
		return model.ScanReport{}, err
	}
	cmd := exec.CommandContext(ctx, path, "scan")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Run the plugin in its own process group so a timeout kills any
	// subprocesses it spawned too, not just the plugin's own top-level
	// process. Without this, an orphaned grandchild that inherited the
	// stdout pipe (e.g. a shell script's own subshells) keeps that pipe
	// open after the plugin is killed, and Wait below blocks until the
	// orphan exits on its own instead of returning at the timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return model.ScanReport{}, fmt.Errorf("%w: %s", err, stderr.String())
	}
	var report model.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return model.ScanReport{}, fmt.Errorf("invalid JSON output: %w", err)
	}
	if report.SchemaVersion != "" && report.SchemaVersion != model.SchemaVersion {
		return model.ScanReport{}, fmt.Errorf("unsupported schemaVersion %q, want %q", report.SchemaVersion, model.SchemaVersion)
	}
	return report, nil
}
