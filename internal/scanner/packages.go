package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
					report.Packages = append(report.Packages, model.Package{
						Manager:  "snap",
						Name:     fields[0],
						Version:  fields[1],
						Decision: model.DecisionCandidate,
						Details:  snapListDetails(fields),
					})
				}
			}
			return
		}
	}
	for _, path := range glob(opts.Root, "/var/lib/snapd/snaps/*.snap", "/snap/*") {
		name := strings.TrimSuffix(filepath.Base(path), ".snap")
		report.Packages = append(report.Packages, model.Package{Manager: "snap", Name: name, Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate, Details: snapPathDetails(opts.Root, path)})
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
					pkg.Details = flatpakCommandDetails(fields)
					report.Packages = append(report.Packages, pkg)
				}
			}
			return
		}
	}
	for _, path := range glob(opts.Root, "/var/lib/flatpak/app/*", "/home/*/.local/share/flatpak/app/*") {
		if info, ok := safeStat(opts.Root, path); ok && info.IsDir() {
			report.Packages = append(report.Packages, model.Package{Manager: "flatpak", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate, Details: flatpakPathDetails(opts.Root, path)})
		}
	}
}

func scanAppImages(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root, "/home/*/Applications/*.AppImage", "/home/*/.local/bin/*.AppImage", "/opt/*.AppImage", "/usr/local/bin/*.AppImage") {
		report.Packages = append(report.Packages, model.Package{Manager: "appimage", Name: strings.TrimSuffix(filepath.Base(path), ".AppImage"), Source: displayPath(opts.Root, path), Decision: model.DecisionMigrationNote, Details: appImageDetails(opts.Root, path)})
	}
}

func scanHomebrewLinux(opts Options, report *model.ScanReport) {
	for _, cellar := range []string{"/home/linuxbrew/.linuxbrew/Cellar", "/opt/homebrew/Cellar"} {
		for _, path := range glob(opts.Root, cellar+"/*") {
			if info, ok := safeStat(opts.Root, path); ok && info.IsDir() {
				report.Packages = append(report.Packages, model.Package{Manager: "homebrew", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate, Details: homebrewDetails(opts.Root, path)})
			}
		}
	}
	for _, path := range glob(opts.Root, "/home/*/.linuxbrew/Cellar/*") {
		if info, ok := safeStat(opts.Root, path); ok && info.IsDir() {
			report.Packages = append(report.Packages, model.Package{Manager: "homebrew", Name: filepath.Base(path), Source: displayPath(opts.Root, path), Decision: model.DecisionCandidate, Details: homebrewDetails(opts.Root, path)})
		}
	}
}

func snapListDetails(fields []string) map[string]string {
	details := map[string]string{}
	if len(fields) > 2 {
		details["revision"] = fields[2]
	}
	if len(fields) > 3 {
		details["tracking"] = fields[3]
	}
	if len(fields) > 4 {
		details["publisher"] = strings.TrimSuffix(fields[4], "*")
	}
	if len(fields) > 5 {
		details["notes"] = strings.Join(fields[5:], ",")
	}
	return emptyPackageDetails(details)
}

func snapPathDetails(root, path string) map[string]string {
	details := map[string]string{"source-kind": "snap-file"}
	display := displayPath(root, path)
	if strings.HasPrefix(display, "/snap/") {
		details["mount"] = "present"
	}
	if strings.HasPrefix(display, "/var/lib/snapd/snaps/") {
		details["store-cache"] = "present"
	}
	return details
}

func flatpakCommandDetails(fields []string) map[string]string {
	details := map[string]string{}
	if len(fields) > 2 && strings.TrimSpace(fields[2]) != "" {
		details["origin"] = strings.TrimSpace(fields[2])
	}
	return emptyPackageDetails(details)
}

func flatpakPathDetails(root, path string) map[string]string {
	details := map[string]string{}
	display := displayPath(root, path)
	if strings.HasPrefix(display, "/var/lib/flatpak/") {
		details["scope"] = "system"
	}
	if strings.Contains(display, "/.local/share/flatpak/") {
		details["scope"] = "user"
	}
	if exists(root, filepath.ToSlash(filepath.Join(display, "current", "active"))) {
		details["current"] = "present"
	}
	metadata := readPackageFile(root, rootPath(root, filepath.ToSlash(filepath.Join(display, "current", "active", "metadata"))))
	mergePackageDetails(details, flatpakMetadataDetails(metadata))
	return emptyPackageDetails(details)
}

func flatpakMetadataDetails(content string) map[string]string {
	details := map[string]string{}
	if content == "" {
		return nil
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	section := ""
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch {
		case section == "Application" && key == "runtime":
			if runtimeName := flatpakRuntimeName(value); runtimeName != "" {
				details["runtime"] = runtimeName
			}
		case section == "Application" && key == "sdk":
			details["sdk"] = "present"
		case section == "Application" && key == "command":
			details["command"] = "present"
		}
	}
	return emptyPackageDetails(details)
}

func flatpakRuntimeName(value string) string {
	parts := strings.Split(value, "/")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func appImageDetails(root, path string) map[string]string {
	details := map[string]string{}
	display := displayPath(root, path)
	switch {
	case strings.Contains(display, "/Applications/"):
		details["location"] = "user-applications"
	case strings.Contains(display, "/.local/bin/"):
		details["location"] = "user-bin"
	case strings.HasPrefix(display, "/opt/"):
		details["location"] = "opt"
	case strings.HasPrefix(display, "/usr/local/bin/"):
		details["location"] = "usr-local-bin"
	}
	if isRegularExecutable(root, path) {
		details["executable"] = "present"
	}
	if version := appImageVersion(filepath.Base(path)); version != "" {
		details["filename-version"] = version
	}
	if appImageDesktopEntryExists(root, path) {
		details["desktop-entry"] = "present"
	}
	return emptyPackageDetails(details)
}

func appImageVersion(name string) string {
	name = strings.TrimSuffix(name, ".AppImage")
	re := regexp.MustCompile(`(?i)(?:^|[-_])v?([0-9]+(?:\.[0-9]+){1,3})(?:[-_]|$)`)
	match := re.FindStringSubmatch(name)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func appImageDesktopEntryExists(root, path string) bool {
	base := strings.TrimSuffix(filepath.Base(path), ".AppImage")
	for _, candidate := range []string{
		strings.TrimSuffix(path, ".AppImage") + ".desktop",
		rootPath(root, "/home/*/.local/share/applications/"+base+".desktop"),
		rootPath(root, "/usr/local/share/applications/"+base+".desktop"),
		rootPath(root, "/usr/share/applications/"+base+".desktop"),
	} {
		if strings.Contains(candidate, "*") {
			matches, _ := filepath.Glob(candidate)
			if len(matches) > 0 {
				return true
			}
			continue
		}
		if _, ok := safeStat(root, candidate); ok {
			return true
		}
	}
	return false
}

func homebrewDetails(root, path string) map[string]string {
	details := map[string]string{}
	display := displayPath(root, path)
	if before, _, ok := strings.Cut(display, "/Cellar/"); ok {
		details["prefix"] = strings.TrimSuffix(before, "/Cellar")
	}
	versions := homebrewVersions(path)
	if len(versions) > 0 {
		details["versions"] = strings.Join(versions, ",")
		details["version-count"] = strconv.Itoa(len(versions))
		if len(versions) == 1 {
			details["current-version"] = versions[0]
		}
	}
	mergePackageDetails(details, homebrewReceiptDetails(root, path, versions))
	return emptyPackageDetails(details)
}

func homebrewVersions(path string) []string {
	var versions []string
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	sort.Strings(versions)
	return versions
}

func homebrewReceiptDetails(root, path string, versions []string) map[string]string {
	details := map[string]string{}
	for _, version := range versions {
		content := readPackageFile(root, filepath.Join(path, version, "INSTALL_RECEIPT.json"))
		if content == "" {
			continue
		}
		var receipt struct {
			Source struct {
				Tap string `json:"tap"`
			} `json:"source"`
			RuntimeDependencies   []json.RawMessage `json:"runtime_dependencies"`
			InstalledAsDependency bool              `json:"installed_as_dependency"`
			InstalledOnRequest    bool              `json:"installed_on_request"`
		}
		if json.Unmarshal([]byte(content), &receipt) != nil {
			continue
		}
		if receipt.Source.Tap != "" {
			details["tap"] = "present"
		}
		if len(receipt.RuntimeDependencies) > 0 {
			details["dependency-count"] = strconv.Itoa(len(receipt.RuntimeDependencies))
		}
		if receipt.InstalledAsDependency {
			details["installed-as-dependency"] = "true"
		}
		if receipt.InstalledOnRequest {
			details["installed-on-request"] = "true"
		}
		break
	}
	return emptyPackageDetails(details)
}

func readPackageFile(root, path string) string {
	b, ok := safeReadFile(root, path)
	if !ok {
		return ""
	}
	return string(b)
}

func mergePackageDetails(dst, src map[string]string) {
	for key, value := range src {
		if value != "" {
			dst[key] = value
		}
	}
}

func emptyPackageDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	return details
}
