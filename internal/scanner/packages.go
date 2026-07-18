package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type PackageEcosystemScanner struct{}

func (PackageEcosystemScanner) Name() string { return "package-ecosystems" }

func (PackageEcosystemScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	scanSnap(ctx, opts, report)
	scanFlatpak(ctx, opts, report)
	scanAppImages(opts, report)
	scanHomebrewLinux(opts, report)
	return nil
}

func scanSnap(ctx context.Context, opts Options, report *model.ScanReport) {
	if opts.Root == "/" && commandAvailable("snap") {
		if out, err := runCommand(ctx, opts.Root, "snap", "list"); err == nil {
			sc := bufio.NewScanner(strings.NewReader(out))
			first := true
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				if first {
					first = false
					if strings.HasPrefix(line, "Name ") {
						continue
					}
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					report.Packages = append(report.Packages, model.Package{Manager: "snap", Name: fields[0], Version: fields[1], Decision: model.DecisionCandidate})
				}
			}
			return
		}
	}
	for _, path := range glob(opts.Root, "/var/lib/snapd/snaps/*.snap", "/snap/*") {
		name := strings.TrimSuffix(filepath.Base(path), ".snap")
		report.Packages = append(report.Packages, model.Package{Manager: "snap", Name: name, Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
	}
}

func scanFlatpak(ctx context.Context, opts Options, report *model.ScanReport) {
	if opts.Root == "/" && commandAvailable("flatpak") {
		if out, err := runCommand(ctx, opts.Root, "flatpak", "list", "--app", "--columns=application,version,origin"); err == nil {
			sc := bufio.NewScanner(strings.NewReader(out))
			for sc.Scan() {
				fields := strings.Split(sc.Text(), "\t")
				if len(fields) >= 1 && strings.TrimSpace(fields[0]) != "" {
					pkg := model.Package{Manager: "flatpak", Name: fields[0], Decision: model.DecisionCandidate}
					if len(fields) > 1 {
						pkg.Version = fields[1]
					}
					if len(fields) > 2 {
						pkg.Source = fields[2]
					}
					report.Packages = append(report.Packages, pkg)
				}
			}
			return
		}
	}
	for _, path := range glob(opts.Root, "/var/lib/flatpak/app/*", "/home/*/.local/share/flatpak/app/*") {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			report.Packages = append(report.Packages, model.Package{Manager: "flatpak", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
		}
	}
}

func scanAppImages(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root, "/home/*/Applications/*.AppImage", "/home/*/.local/bin/*.AppImage", "/opt/*.AppImage", "/usr/local/bin/*.AppImage") {
		report.Packages = append(report.Packages, model.Package{Manager: "appimage", Name: strings.TrimSuffix(filepath.Base(path), ".AppImage"), Source: displayPath(opts.Root, path), Decision: model.DecisionMigrationNote})
	}
}

func scanHomebrewLinux(opts Options, report *model.ScanReport) {
	for _, cellar := range []string{"/home/linuxbrew/.linuxbrew/Cellar", "/opt/homebrew/Cellar"} {
		for _, path := range glob(opts.Root, cellar+"/*") {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				report.Packages = append(report.Packages, model.Package{Manager: "homebrew", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
			}
		}
	}
	for _, path := range glob(opts.Root, "/home/*/.linuxbrew/Cellar/*") {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			report.Packages = append(report.Packages, model.Package{Manager: "homebrew", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
		}
	}
}
