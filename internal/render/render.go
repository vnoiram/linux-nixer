package render

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func Project(out string, report model.ScanReport) error {
	dirs := []string{
		out,
		filepath.Join(out, "hosts", "generated"),
		filepath.Join(out, "users"),
		filepath.Join(out, "modules"),
		filepath.Join(out, "reports"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	host := report.Host.Hostname
	if host == "" {
		host = "generated"
	}
	hostAttr := sanitizeNixAttr(host)
	user := primaryUser(report)
	files := map[string]string{
		"flake.nix":                         renderTemplate(flakeTemplate, data{Host: host, HostAttr: hostAttr, User: user, Report: report}),
		"hosts/generated/configuration.nix": renderTemplate(hostTemplate, data{Host: host, HostAttr: hostAttr, User: user, Report: report}),
		"users/home.nix":                    renderTemplate(homeTemplate, data{Host: host, HostAttr: hostAttr, User: user, Report: report}),
		"modules/containers.nix":            renderTemplate(containersTemplate, data{Host: host, HostAttr: hostAttr, User: user, Report: report}),
		"modules/services.nix":              renderServicesModule(report),
		"modules/filesystem-findings.nix":   renderFilesystemModule(report),
		"reports/dev-projects.md":           renderDevProjectsReport(report),
		"reports/desktop.md":                renderDesktopReport(report),
		"reports/migration-report.md":       renderReport(report),
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(out, rel), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

type data struct {
	Host     string
	HostAttr string
	User     model.User
	Report   model.ScanReport
}

func renderTemplate(tpl string, d data) string {
	t := template.Must(template.New("nix").Funcs(template.FuncMap{
		"nixList":           nixList,
		"quote":             quote,
		"systemPackages":    packageNames,
		"homePackages":      homePackageNames,
		"bool":              nixBool,
		"dockerDetected":    dockerDetected,
		"podmanDetected":    podmanDetected,
		"todoComments":      todoComments,
		"containerComments": containerComments,
	}).Parse(tpl))
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		panic(err)
	}
	return buf.String()
}

func nixList(values []string) string {
	if len(values) == 0 {
		return "[ ]"
	}
	sort.Strings(values)
	var b strings.Builder
	b.WriteString("[\n")
	for _, v := range values {
		b.WriteString("    ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	b.WriteString("  ]")
	return b.String()
}

func quote(s string) string {
	return fmt.Sprintf("%q", s)
}

func nixBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func packageNames(report model.ScanReport) []string {
	seen := map[string]bool{}
	var names []string
	for _, pkg := range report.Packages {
		if pkg.Decision != model.DecisionConfirmed {
			continue
		}
		if len(pkg.NixNames) == 0 {
			continue
		}
		name := "pkgs." + pkg.NixNames[0]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func homePackageNames(report model.ScanReport) []string {
	seen := map[string]bool{}
	var names []string
	add := func(pkg model.Package) {
		if pkg.Decision != model.DecisionConfirmed || len(pkg.NixNames) == 0 {
			return
		}
		name := "pkgs." + pkg.NixNames[0]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, pkg := range report.Languages.NPM {
		add(pkg)
	}
	for _, pkg := range report.Languages.Conda {
		add(pkg)
	}
	for _, pkg := range report.Languages.Cargo {
		add(pkg)
	}
	for _, pkg := range report.Languages.Gem {
		add(pkg)
	}
	for _, pkg := range report.Languages.Go {
		add(pkg)
	}
	for _, env := range report.Languages.Python {
		for _, pkg := range env.Packages {
			add(pkg)
		}
	}
	return names
}

func dockerDetected(report model.ScanReport) bool {
	for _, c := range report.Containers {
		if c.Decision == model.DecisionConfirmed && (c.Runtime == "docker" || c.Runtime == "compose") {
			return true
		}
	}
	return false
}

func podmanDetected(report model.ScanReport) bool {
	for _, c := range report.Containers {
		if c.Decision == model.DecisionConfirmed && c.Runtime == "podman" {
			return true
		}
	}
	return false
}

func includeDecision(decision model.Decision) bool {
	return decision == "" || decision == model.DecisionConfirmed || decision == model.DecisionCandidate
}

func reportDecision(decision model.Decision) bool {
	return decision == "" || decision == model.DecisionConfirmed || decision == model.DecisionCandidate || decision == model.DecisionTODO || decision == model.DecisionMigrationNote
}

func primaryUser(report model.ScanReport) model.User {
	for _, user := range report.Users {
		if !user.System && user.Name != "root" && strings.HasPrefix(user.Home, "/home/") {
			return user
		}
	}
	return model.User{Name: "generated", Home: "/home/generated"}
}

func sanitizeNixAttr(value string) string {
	if value == "" {
		return "generated"
	}
	prefix := ""
	runes := []rune(value)
	first := runes[0]
	if first >= '0' && first <= '9' {
		prefix = "host_"
	}
	var out []rune
	for i, r := range runes {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		if i > 0 {
			ok = ok || (r >= '0' && r <= '9')
		} else if prefix != "" {
			ok = ok || (r >= '0' && r <= '9')
		}
		if ok {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	if len(out) == 0 || out[0] == '_' && prefix == "" {
		return "generated" + string(out)
	}
	return prefix + string(out)
}

func renderReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# linux-nixer migration report\n\n")
	b.WriteString("## Host\n\n")
	b.WriteString(fmt.Sprintf("- Distro: %s %s\n", report.Host.Distro, report.Host.Release))
	b.WriteString(fmt.Sprintf("- Hostname: %s\n\n", report.Host.Hostname))
	b.WriteString("## Packages\n\n")
	for _, pkg := range report.Packages {
		if !reportDecision(pkg.Decision) {
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s` via %s", pkg.Name, pkg.Manager))
		if len(pkg.NixNames) > 0 {
			b.WriteString(fmt.Sprintf(" -> `%s`", pkg.NixNames[0]))
		} else {
			b.WriteString(" (no nix mapping)")
		}
		if pkg.Decision != "" {
			b.WriteString(fmt.Sprintf(" [%s]", pkg.Decision))
		}
		b.WriteString("\n")
	}
	writeLanguagePackages(&b, report)
	b.WriteString("\n## Services\n\n")
	for _, service := range report.Services {
		if reportDecision(service.Decision) {
			b.WriteString(fmt.Sprintf("- `%s` %s `%s` [%s]\n", service.Name, service.Manager, service.Path, printableDecision(service.Decision)))
		}
	}
	b.WriteString("\n## Containers\n\n")
	for _, container := range report.Containers {
		if reportDecision(container.Decision) {
			b.WriteString("- ")
			b.WriteString(containerSummary(container))
			b.WriteString(fmt.Sprintf(" [%s]\n", printableDecision(container.Decision)))
		}
	}
	b.WriteString("\n## Desktop\n\n")
	if report.Desktop.Environment != "" {
		b.WriteString(fmt.Sprintf("- Environment: %s\n", report.Desktop.Environment))
	}
	b.WriteString(fmt.Sprintf("- Fonts: %d\n", len(report.Desktop.Fonts)))
	b.WriteString(fmt.Sprintf("- Themes/icons: %d\n", len(report.Desktop.Themes)))
	b.WriteString(fmt.Sprintf("- Autostart entries: %d\n", len(report.Desktop.Autostart)))
	for _, item := range desktopConfigItems(report) {
		b.WriteString(fmt.Sprintf("- `%s` %s [%s]\n", item.Path, item.Kind, printableDecision(item.Decision)))
	}
	b.WriteString("\n## Dev projects\n\n")
	for _, item := range devProjectItems(report) {
		b.WriteString(fmt.Sprintf("- `%s` %s\n", item.Path, item.Kind))
	}
	b.WriteString("\n## Filesystem findings\n\n")
	for _, f := range report.FilesystemDiff {
		if !reportDecision(f.Decision) {
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s` %s %s\n", f.Path, f.Type, f.Reason))
	}
	b.WriteString("\n## Stateful data and manual migration notes\n\n")
	for _, f := range report.StatefulData {
		b.WriteString(fmt.Sprintf("- `%s` %s\n", f.Path, f.Reason))
	}
	for _, item := range report.Items {
		if item.Decision == model.DecisionTODO || item.Decision == model.DecisionMigrationNote || item.Decision == model.DecisionCandidate {
			b.WriteString(fmt.Sprintf("- `%s` %s %s\n", item.Path, item.Kind, item.Reason))
		}
	}
	if len(report.Warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		for _, w := range report.Warnings {
			b.WriteString(fmt.Sprintf("- %s: %s\n", w.Source, w.Message))
		}
	}
	return b.String()
}

func writeLanguagePackages(b *strings.Builder, report model.ScanReport) {
	sections := []struct {
		name string
		pkgs []model.Package
	}{
		{"npm", report.Languages.NPM},
		{"conda", report.Languages.Conda},
		{"cargo", report.Languages.Cargo},
		{"gem", report.Languages.Gem},
		{"go", report.Languages.Go},
	}
	for _, section := range sections {
		for _, pkg := range section.pkgs {
			if reportDecision(pkg.Decision) {
				b.WriteString(languagePackageLine(pkg, ""))
			}
		}
	}
	for _, env := range report.Languages.Python {
		for _, pkg := range env.Packages {
			if reportDecision(pkg.Decision) {
				b.WriteString(languagePackageLine(pkg, env.Path))
			}
		}
	}
}

func languagePackageLine(pkg model.Package, envPath string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("- `%s` via %s", pkg.Name, pkg.Manager))
	if envPath != "" {
		b.WriteString(fmt.Sprintf(" in `%s`", envPath))
	}
	if len(pkg.NixNames) > 0 {
		b.WriteString(fmt.Sprintf(" -> `%s`", pkg.NixNames[0]))
	} else {
		b.WriteString(" (no nix mapping)")
	}
	b.WriteString(fmt.Sprintf(" [%s]\n", printableDecision(pkg.Decision)))
	return b.String()
}

func renderServicesModule(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Generated by linux-nixer. Review and translate TODOs into NixOS options.\n")
	b.WriteString("{ config, pkgs, ... }:\n\n{\n")
	for _, service := range report.Services {
		if !includeDecision(service.Decision) {
			continue
		}
		b.WriteString("  # TODO service: ")
		b.WriteString(comment(fmt.Sprintf("%s %s at %s [%s]", service.Manager, service.Name, service.Path, printableDecision(service.Decision))))
		b.WriteString("\n")
	}
	for _, item := range report.Items {
		if !includeDecision(item.Decision) || !isServiceLikeItem(item) {
			continue
		}
		b.WriteString("  # TODO config: ")
		b.WriteString(comment(fmt.Sprintf("%s at %s %s", item.Kind, item.Path, item.Reason)))
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func renderFilesystemModule(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Generated by linux-nixer. Files are not copied automatically.\n")
	b.WriteString("{ config, pkgs, ... }:\n\n{\n")
	for _, f := range report.FilesystemDiff {
		if !includeDecision(f.Decision) {
			continue
		}
		b.WriteString("  # TODO filesystem: ")
		b.WriteString(comment(fmt.Sprintf("%s %s %s [%s]", f.Category, f.Path, f.Reason, printableDecision(f.Decision))))
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func renderDevProjectsReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Development project findings\n\n")
	for _, item := range devProjectItems(report) {
		b.WriteString(fmt.Sprintf("- `%s` %s", item.Path, item.Kind))
		if item.Reason != "" {
			b.WriteString(": ")
			b.WriteString(item.Reason)
		}
		b.WriteString("\n")
	}
	if len(report.Languages.VMs) > 0 {
		b.WriteString("\n## Version managers\n\n")
		for _, vm := range report.Languages.VMs {
			b.WriteString(fmt.Sprintf("- `%s` at `%s`\n", vm.Name, vm.Path))
		}
	}
	return b.String()
}

func renderDesktopReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Desktop findings\n\n")
	if report.Desktop.Environment != "" {
		b.WriteString(fmt.Sprintf("- Environment: %s\n", report.Desktop.Environment))
	} else {
		b.WriteString("- Environment: unknown\n")
	}
	if len(report.Desktop.Fonts) > 0 {
		b.WriteString("\n## Fonts\n\n")
		for _, path := range report.Desktop.Fonts {
			b.WriteString(fmt.Sprintf("- `%s`\n", path))
		}
	}
	if len(report.Desktop.Themes) > 0 {
		b.WriteString("\n## Themes and icons\n\n")
		for _, path := range report.Desktop.Themes {
			b.WriteString(fmt.Sprintf("- `%s`\n", path))
		}
	}
	if len(report.Desktop.Autostart) > 0 {
		b.WriteString("\n## Autostart\n\n")
		for _, finding := range report.Desktop.Autostart {
			if reportDecision(finding.Decision) {
				b.WriteString(fmt.Sprintf("- `%s` [%s]\n", finding.Path, printableDecision(finding.Decision)))
			}
		}
	}
	items := desktopConfigItems(report)
	if len(items) > 0 {
		b.WriteString("\n## Config files\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Reason != "" {
				b.WriteString(": ")
				b.WriteString(item.Reason)
			}
			b.WriteString("\n")
		}
	}
	if len(report.Desktop.Dconf) > 0 {
		b.WriteString("\n## Dconf dump\n\n")
		b.WriteString("```ini\n")
		for _, line := range report.Desktop.Dconf {
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	}
	return b.String()
}

func todoComments(report model.ScanReport) []string {
	var lines []string
	for _, item := range report.Items {
		if includeDecision(item.Decision) && (item.Kind == "user-config" || item.Kind == "direnv" || item.Kind == "desktop-config") {
			lines = append(lines, comment(fmt.Sprintf("%s at %s %s", item.Kind, item.Path, item.Reason)))
		}
	}
	for _, env := range report.Languages.Python {
		if env.Kind == "pipx" || env.Kind == "venv" {
			lines = append(lines, comment(fmt.Sprintf("python %s at %s", env.Kind, env.Path)))
		}
	}
	return lines
}

func containerComments(report model.ScanReport) []string {
	var lines []string
	for _, c := range report.Containers {
		if includeDecision(c.Decision) {
			lines = append(lines, fmt.Sprintf("%s [%s]", containerSummary(c), printableDecision(c.Decision)))
		}
	}
	return lines
}

func devProjectItems(report model.ScanReport) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && (item.Kind == "dev-project" || item.Kind == "direnv") {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func desktopConfigItems(report model.ScanReport) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && item.Kind == "desktop-config" {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func isServiceLikeItem(item model.Item) bool {
	if item.Kind != "os-config" {
		return false
	}
	path := item.Path
	return strings.Contains(path, "/nginx/") ||
		strings.Contains(path, "/apache2/") ||
		strings.Contains(path, "/NetworkManager/") ||
		strings.Contains(path, "/netplan/") ||
		strings.Contains(path, "/udev/") ||
		strings.Contains(path, "/logrotate") ||
		strings.Contains(path, "nftables") ||
		strings.Contains(path, "ufw") ||
		strings.Contains(path, "sysctl")
}

func containerSummary(c model.Container) string {
	switch {
	case c.Compose != "":
		return fmt.Sprintf("compose `%s`", c.Compose)
	case c.Name != "" && c.Image != "":
		return fmt.Sprintf("%s container `%s` image `%s`", c.Runtime, c.Name, c.Image)
	case c.Image != "":
		return fmt.Sprintf("%s image `%s`", c.Runtime, c.Image)
	default:
		return fmt.Sprintf("%s container finding", c.Runtime)
	}
}

func printableDecision(decision model.Decision) model.Decision {
	if decision == "" {
		return model.DecisionCandidate
	}
	return decision
}

func comment(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}

var flakeTemplate = `{
  description = "Generated by linux-nixer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager.url = "github:nix-community/home-manager";
    home-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, home-manager, ... }: {
    nixosConfigurations.{{ .HostAttr }} = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./hosts/generated/configuration.nix
        home-manager.nixosModules.home-manager
        {
          home-manager.useGlobalPkgs = true;
          home-manager.useUserPackages = true;
          home-manager.users.{{ quote .User.Name }} = import ./users/home.nix;
        }
      ];
    };
  };
}
`

var hostTemplate = `# Generated by linux-nixer. Review before applying.
{ config, pkgs, ... }:

{
  networking.hostName = {{ quote .Report.Host.Hostname }};
  time.timeZone = "UTC";

  environment.systemPackages = with pkgs; {{ nixList (systemPackages .Report) }};

  imports = [
    ../../modules/containers.nix
    ../../modules/services.nix
    ../../modules/filesystem-findings.nix
  ];
}
`

var homeTemplate = `# Generated by linux-nixer. Review before applying.
{ config, pkgs, ... }:

{
  home.username = {{ quote .User.Name }};
  home.homeDirectory = {{ quote .User.Home }};
  home.stateVersion = "24.05";
  programs.home-manager.enable = true;
  home.packages = {{ nixList (homePackages .Report) }};

{{- range todoComments .Report }}
  # TODO home: {{ . }}
{{- end }}
}
`

var containersTemplate = `# Generated by linux-nixer. Container details are reported in reports/migration-report.md.
{ config, pkgs, ... }:

{
  virtualisation.docker.enable = {{ bool (dockerDetected .Report) }};
  virtualisation.podman.enable = {{ bool (podmanDetected .Report) }};

{{- range containerComments .Report }}
  # TODO container: {{ . }}
{{- end }}
}
`
