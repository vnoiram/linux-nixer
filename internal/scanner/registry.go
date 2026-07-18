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
}

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
		LanguageScanner{},
		GitScanner{},
		ContainerScanner{},
		ConfigScanner{},
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

func readText(root, path string) (string, error) {
	b, err := os.ReadFile(rootPath(root, path))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func exists(root, path string) bool {
	_, err := os.Stat(rootPath(root, path))
	return err == nil
}
