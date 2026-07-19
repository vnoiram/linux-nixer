package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type Options struct {
	Root       string
	UseSudo    bool
	Deep       bool
	BaselineID string
	Includes   []string
	Excludes   []string
	Runner     CommandRunner
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type Scanner interface {
	Name() string
	Scan(context.Context, Options, *model.ScanReport) error
}

type Registry struct {
	scanners []Scanner
}

func New(scanners ...Scanner) Registry {
	return Registry{scanners: scanners}
}

func DefaultRegistry() Registry {
	return New(
		HostScanner{},
		UserScanner{},
		AptScanner{},
		PackageEcosystemScanner{},
		LanguageScanner{},
		GitScanner{},
		ContainerScanner{},
		StatefulDataScanner{},
		BackupConfigScanner{},
		SystemConfigScanner{},
		DevOpsConfigScanner{},
		ProjectConfigScanner{},
		UserConfigScanner{},
		DesktopScanner{},
		SecretScanner{},
		FilesystemDiffScanner{},
	)
}

func (r Registry) Scan(ctx context.Context, opts Options) (*model.ScanReport, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	report := &model.ScanReport{SchemaVersion: model.SchemaVersion}
	for _, s := range r.scanners {
		if err := s.Scan(ctx, opts, report); err != nil {
			report.Warnings = append(report.Warnings, model.Warning{Source: s.Name(), Message: err.Error()})
		}
	}
	return report, nil
}

func rootPath(root, path string) string {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return filepath.Clean(root)
	}
	return filepath.Join(root, path)
}

func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	if rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCommand(ctx context.Context, root string, name string, args ...string) (string, error) {
	if root != "/" {
		return "", fmt.Errorf("external command %s skipped for non-host root %s", name, root)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func readText(ctx context.Context, opts Options, report *model.ScanReport, source, path string) (string, error) {
	b, err := readFile(ctx, opts, report, source, path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func exists(root, path string) bool {
	_, err := os.Stat(rootPath(root, path))
	return err == nil
}

func existsWithSudo(ctx context.Context, opts Options, report *model.ScanReport, source, path string) bool {
	if exists(opts.Root, path) {
		return true
	}
	if !canUseSudo(opts) {
		return false
	}
	if opts.Runner == nil && !commandAvailable("sudo") {
		report.Warnings = append(report.Warnings, model.Warning{Source: source, Message: "sudo unavailable; could not check " + path})
		return false
	}
	if _, err := runWithOptions(ctx, opts, "sudo", "test", "-e", path); err != nil {
		return false
	}
	report.Warnings = append(report.Warnings, model.Warning{Source: source, Message: "sudo fallback used to check " + path})
	return true
}

func readFile(ctx context.Context, opts Options, report *model.ScanReport, source, path string) ([]byte, error) {
	b, err := os.ReadFile(rootPath(opts.Root, path))
	if err == nil {
		return b, nil
	}
	if !canUseSudo(opts) {
		return nil, err
	}
	if opts.Runner == nil && !commandAvailable("sudo") {
		report.Warnings = append(report.Warnings, model.Warning{Source: source, Message: "sudo unavailable; could not read " + path})
		return nil, err
	}
	out, sudoErr := runWithOptions(ctx, opts, "sudo", "cat", path)
	if sudoErr != nil {
		return nil, err
	}
	report.Warnings = append(report.Warnings, model.Warning{Source: source, Message: "sudo fallback used to read " + path})
	return out, nil
}

func runWithOptions(ctx context.Context, opts Options, name string, args ...string) ([]byte, error) {
	if opts.Runner != nil {
		return opts.Runner(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func canUseSudo(opts Options) bool {
	return opts.UseSudo && opts.Root == "/"
}
