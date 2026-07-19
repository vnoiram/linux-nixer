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
		"reports/package-sources.md":        renderPackageSourcesReport(report),
		"reports/filesystem.md":             renderFilesystemReport(report),
		"reports/users.md":                  renderUsersReport(report),
		"reports/containers.md":             renderContainersReport(report),
		"reports/git-sources.md":            renderGitSourcesReport(report),
		"reports/languages.md":              renderLanguagesReport(report),
		"reports/system-config.md":          renderSystemConfigReport(report),
		"reports/devops-config.md":          renderDevOpsConfigReport(report),
		"reports/dev-projects.md":           renderDevProjectsReport(report),
		"reports/user-config.md":            renderUserConfigReport(report),
		"reports/desktop.md":                renderDesktopReport(report),
		"reports/migration-report.md":       renderReport(report),
		"reports/migration-checklist.md":    renderMigrationChecklist(report),
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
		"nixList":            nixList,
		"quote":              quote,
		"systemPackages":     packageNames,
		"homePackages":       homePackageNames,
		"bool":               nixBool,
		"dockerDetected":     dockerDetected,
		"podmanDetected":     podmanDetected,
		"todoComments":       todoComments,
		"containerComments":  containerComments,
		"hostUserOptions":    hostUserOptions,
		"hostShellOptions":   hostShellOptions,
		"homeProgramOptions": homeProgramOptions,
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

func hostShellOptions(report model.ScanReport) string {
	var lines []string
	for _, shell := range generatedHostShells(report) {
		switch shell {
		case "zsh":
			lines = append(lines, "  programs.zsh.enable = true;")
		case "fish":
			lines = append(lines, "  programs.fish.enable = true;")
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n" + strings.Join(lines, "\n") + "\n"
}

func hostUserOptions(report model.ScanReport) string {
	users := nixUsers(report)
	if len(users) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, user := range users {
		b.WriteString(fmt.Sprintf("  users.users.%s = {\n", quote(user.Name)))
		b.WriteString("    isNormalUser = true;\n")
		if user.Home != "" {
			b.WriteString(fmt.Sprintf("    home = %s;\n", quote(user.Home)))
		}
		if groups := nixUserGroups(user); len(groups) > 0 {
			b.WriteString("    extraGroups = ")
			b.WriteString(nixStringList(groups, 4))
			b.WriteString(";\n")
		}
		if shell := nixShellPackage(user.Shell); shell != "" {
			b.WriteString(fmt.Sprintf("    shell = %s;\n", shell))
		}
		b.WriteString("  };\n")
	}
	return b.String()
}

func homeProgramOptions(report model.ScanReport) string {
	var lines []string
	for _, program := range generatedHomePrograms(report) {
		lines = append(lines, fmt.Sprintf("  programs.%s.enable = true;", program))
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n" + strings.Join(lines, "\n") + "\n"
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

func manualDecision(decision model.Decision) bool {
	return decision == "" || decision == model.DecisionCandidate || decision == model.DecisionTODO || decision == model.DecisionMigrationNote
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
	writeGeneratedNixSummary(&b, report)
	b.WriteString("## Users\n\n")
	user := primaryUser(report)
	b.WriteString(fmt.Sprintf("- Primary Home Manager user: `%s` home `%s`\n", user.Name, user.Home))
	for _, user := range privilegedUsers(report) {
		b.WriteString(fmt.Sprintf("- Privileged or group-sensitive user: `%s` groups `%s`\n", user.Name, strings.Join(user.Groups, ", ")))
	}
	for _, user := range humanUsers(report) {
		b.WriteString(userLine(user))
	}
	b.WriteString("\n")
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
		if pkg.Source != "" {
			b.WriteString(fmt.Sprintf(" source `%s`", pkg.Source))
		}
		b.WriteString("\n")
	}
	for _, item := range packageSourceItems(report) {
		b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Kind, printableDecision(item.Decision)))
		if item.Source != "" {
			b.WriteString(fmt.Sprintf(" source `%s`", item.Source))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Language packages\n\n")
	writeLanguagePackages(&b, report)
	for _, vm := range report.Languages.VMs {
		b.WriteString(fmt.Sprintf("- version manager `%s` at `%s`\n", vm.Name, vm.Path))
	}
	for _, item := range languageProjectItems(report) {
		b.WriteString(fmt.Sprintf("- `%s` %s [%s]\n", item.Path, item.Reason, printableDecision(item.Decision)))
	}
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
	b.WriteString("\n## Git sources\n\n")
	for _, source := range gitSources(report) {
		b.WriteString(fmt.Sprintf("- `%s`", source.Path))
		if source.Remote != "" {
			b.WriteString(fmt.Sprintf(" remote `%s`", source.Remote))
		}
		if source.Commit != "" {
			b.WriteString(fmt.Sprintf(" commit `%s`", source.Commit))
		}
		if source.Dirty {
			b.WriteString(" dirty")
		}
		b.WriteString(fmt.Sprintf(" [%s]\n", printableDecision(source.Decision)))
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
	b.WriteString("\n## User config\n\n")
	for _, item := range userConfigItems(report) {
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
		b.WriteString(fileFindingLine(f))
	}
	b.WriteString("\n## Stateful data and manual migration notes\n\n")
	for _, f := range report.StatefulData {
		if reportDecision(f.Decision) {
			b.WriteString(fileFindingLine(f))
		}
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

func writeGeneratedNixSummary(b *strings.Builder, report model.ScanReport) {
	var lines []string
	for _, user := range nixUsers(report) {
		lines = append(lines, fmt.Sprintf("- user option: `users.users.%s`", user.Name))
	}
	for _, shell := range generatedHostShells(report) {
		lines = append(lines, fmt.Sprintf("- host shell option: `programs.%s.enable`", shell))
	}
	for _, program := range generatedHomePrograms(report) {
		lines = append(lines, fmt.Sprintf("- Home Manager option: `programs.%s.enable`", program))
	}
	for _, service := range report.Services {
		if service.Decision == model.DecisionConfirmed && service.Manager == "systemd" {
			lines = append(lines, fmt.Sprintf("- service hint: `systemd.services.%s.enable`", serviceNameAttr(service.Name)))
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("## Generated Nix summary\n\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func renderMigrationChecklist(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Manual migration checklist\n\n")
	b.WriteString("Use this checklist after reviewing `reviewed.json` and before applying generated Nix. Do not commit raw secrets, credentials, or stateful data.\n\n")
	writeChecklistSection(&b, "Before applying Nix", []string{
		"Run `linux-nixer validate --scan reviewed.json --strict` and resolve validation errors.",
		"Run `linux-nixer summary --scan reviewed.json --fail-on-pending` when you want to enforce that all candidates and TODOs are reviewed.",
		"Review generated Nix files and reports before switching the target host.",
	})
	writePackageChecklist(&b, report)
	writeAptSourceChecklist(&b, report)
	writeLanguageChecklist(&b, report)
	writeServiceChecklist(&b, report)
	writeContainerChecklist(&b, report)
	writeGitChecklist(&b, report)
	writeFilesystemChecklist(&b, report)
	writeSecretChecklist(&b, report)
	writeStatefulChecklist(&b, report)
	writeUserDesktopChecklist(&b, report)
	return b.String()
}

func writeChecklistSection(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("## ")
	b.WriteString(title)
	b.WriteString("\n\n")
	for _, item := range items {
		b.WriteString("- [ ] ")
		b.WriteString(item)
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writePackageChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, pkg := range report.Packages {
		if !manualDecision(pkg.Decision) {
			continue
		}
		if len(pkg.NixNames) > 0 {
			items = append(items, fmt.Sprintf("Confirm whether `%s` via %s should be promoted to `confirmed` and rendered as `%s`.", pkg.Name, pkg.Manager, pkg.NixNames[0]))
		} else {
			items = append(items, fmt.Sprintf("Find or package a Nix equivalent for `%s` via %s, or keep it as a documented manual install.", pkg.Name, pkg.Manager))
		}
	}
	writeChecklistSection(b, "Packages", items)
}

func writeAptSourceChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, item := range packageSourceItems(report) {
		if !manualDecision(item.Decision) {
			continue
		}
		switch item.Kind {
		case "apt-source":
			items = append(items, fmt.Sprintf("Recreate apt repository `%s` manually or replace it with nixpkgs/flakes inputs.", item.Path))
		case "apt-keyring":
			items = append(items, fmt.Sprintf("Recreate apt keyring `%s` only if the repository is still needed; do not embed trust keys blindly.", item.Path))
		case "apt-preference":
			items = append(items, fmt.Sprintf("Translate apt pinning/preference `%s` into an explicit Nix package source decision.", item.Path))
		case "apt-config":
			items = append(items, fmt.Sprintf("Review apt client configuration `%s` and decide whether it is still relevant on NixOS.", item.Path))
		}
	}
	writeChecklistSection(b, "Apt sources", items)
}

func writeLanguageChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	add := func(pkg model.Package) {
		if !manualDecision(pkg.Decision) {
			return
		}
		if len(pkg.NixNames) > 0 {
			items = append(items, fmt.Sprintf("Confirm `%s` from %s as a Home Manager package `%s`, or leave it project-local.", pkg.Name, pkg.Manager, pkg.NixNames[0]))
		} else {
			items = append(items, fmt.Sprintf("Decide how to recreate `%s` from %s: nixpkgs package, project dev shell, or manual installer.", pkg.Name, pkg.Manager))
		}
	}
	for _, pkgs := range [][]model.Package{report.Languages.NPM, report.Languages.Conda, report.Languages.Cargo, report.Languages.Gem, report.Languages.Go} {
		for _, pkg := range pkgs {
			add(pkg)
		}
	}
	for _, env := range report.Languages.Python {
		for _, pkg := range env.Packages {
			add(pkg)
		}
		if len(env.Packages) == 0 {
			items = append(items, fmt.Sprintf("Inspect Python %s environment `%s` and decide whether to recreate it with a dev shell, venv, uv, Poetry, or pipx.", env.Kind, env.Path))
		}
	}
	for _, item := range languageProjectItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Review project dependency file `%s` and decide whether it needs a dev shell or project-specific flake.", item.Path))
		}
	}
	writeChecklistSection(b, "Language ecosystems", items)
}

func writeServiceChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, service := range systemServices(report) {
		if !manualDecision(service.Decision) {
			continue
		}
		items = append(items, serviceChecklistItem(service))
	}
	for _, item := range systemConfigItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, systemConfigChecklistItem(item))
		}
	}
	writeChecklistSection(b, "Services", items)
}

func systemConfigChecklistItem(item model.Item) string {
	action := fmt.Sprintf("Translate system configuration `%s` (%s) into NixOS options or keep it as a manual note.", item.Path, item.Reason)
	details := itemDetails(item)
	if len(details) == 0 {
		return action
	}
	if len(details) > 4 {
		details = details[:4]
	}
	return strings.TrimSuffix(action, ".") + ". Review " + strings.Join(details, ", ") + "."
}

func serviceChecklistItem(service model.Service) string {
	action := fmt.Sprintf("Translate %s service `%s` from `%s` into a NixOS service/module or document manual setup.", service.Manager, service.Name, service.Path)
	var details []string
	if service.ExecStart != "" {
		details = append(details, "exec `"+redactSecretLikeText(service.ExecStart)+"`")
	}
	if service.User != "" {
		details = append(details, "user `"+service.User+"`")
	}
	if service.WorkingDirectory != "" {
		details = append(details, "working directory `"+service.WorkingDirectory+"`")
	}
	if service.Schedule != "" {
		details = append(details, "schedule `"+service.Schedule+"`")
	}
	if len(details) > 0 {
		action += " Review " + strings.Join(details, ", ") + "."
	}
	return action
}

func writeContainerChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, container := range report.Containers {
		if !manualDecision(container.Decision) {
			continue
		}
		items = append(items, fmt.Sprintf("Translate %s into Nix/container config, including image, ports, mounts, volumes, and redacted env keys.", containerSummary(container)))
	}
	writeChecklistSection(b, "Containers", items)
}

func writeGitChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, source := range gitSources(report) {
		if !manualDecision(source.Decision) {
			continue
		}
		action := fmt.Sprintf("Decide clone/build strategy for Git source `%s`", source.Path)
		if source.Remote != "" {
			action += fmt.Sprintf(" from `%s`", source.Remote)
		}
		if source.Commit != "" {
			action += fmt.Sprintf(" at commit `%s`", source.Commit)
		}
		if source.Dirty {
			action += "; backup dirty changes before migration"
		}
		if len(source.Build) > 0 {
			action += fmt.Sprintf("; review build hints `%s`", strings.Join(source.Build, ", "))
		}
		items = append(items, action+".")
	}
	writeChecklistSection(b, "Git sources", items)
}

func writeFilesystemChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, finding := range filesystemFindings(report) {
		if finding.SecretRisk || !manualDecision(finding.Decision) {
			continue
		}
		items = append(items, fmt.Sprintf("Decide how to recreate `%s` (%s/%s): package it, copy it manually, or replace it with a NixOS/Home Manager option.", finding.Path, finding.Category, finding.Type))
	}
	writeChecklistSection(b, "Filesystem", items)
}

func writeSecretChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, finding := range filesystemFindings(report) {
		if finding.SecretRisk {
			items = append(items, fmt.Sprintf("Back up and restore secret-risk file `%s` manually; do not commit raw contents to Nix or Git.", finding.Path))
		}
	}
	for _, item := range report.Items {
		if reportDecision(item.Decision) && (item.Decision == model.DecisionMigrationNote || secretLikeReason(item.Reason)) && item.Path != "" {
			items = append(items, fmt.Sprintf("Recreate credential-bearing config `%s` manually or through a secrets manager; do not commit raw contents.", item.Path))
		}
	}
	writeChecklistSection(b, "Secrets and credentials", items)
}

func writeStatefulChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, finding := range statefulFindings(report) {
		reason := ""
		if finding.Reason != "" {
			reason = fmt.Sprintf(" (%s)", finding.Reason)
		}
		items = append(items, fmt.Sprintf("Back up stateful data `%s`%s and define a restore procedure before switching systems.", finding.Path, reason))
	}
	writeChecklistSection(b, "Stateful data", items)
}

func writeUserDesktopChecklist(b *strings.Builder, report model.ScanReport) {
	var items []string
	for _, user := range humanUsers(report) {
		items = append(items, fmt.Sprintf("Confirm user `%s` home `%s`, shell `%s`, and required groups before applying user options.", user.Name, user.Home, user.Shell))
	}
	for _, item := range userConfigItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Review user configuration `%s` (%s) and decide whether to translate it to Home Manager.", item.Path, item.Kind))
		}
	}
	for _, item := range desktopConfigItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Review desktop configuration `%s` and decide whether to translate it to Home Manager or keep it manual.", item.Path))
		}
	}
	for _, item := range browserProfileItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Back up or sync browser profile `%s` manually; review cookies, history, sessions, and credentials before migration.", item.Path))
		}
	}
	for _, item := range browserExtensionItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Review browser extension marker `%s` and decide whether to reinstall through browser sync or manual export.", item.Path))
		}
	}
	for _, item := range editorProfileItems(report) {
		if manualDecision(item.Decision) {
			items = append(items, fmt.Sprintf("Review editor profile `%s` and decide whether to recreate it with Home Manager, Settings Sync, or manual restore.", item.Path))
		}
	}
	for _, finding := range report.Desktop.Autostart {
		if reportDecision(finding.Decision) {
			items = append(items, fmt.Sprintf("Review desktop autostart entry `%s` and decide whether to translate it to Home Manager.", finding.Path))
		}
	}
	writeChecklistSection(b, "Users and desktop config", items)
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

func packageLine(pkg model.Package) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("- `%s` via %s", pkg.Name, pkg.Manager))
	if len(pkg.NixNames) > 0 {
		b.WriteString(fmt.Sprintf(" -> `%s`", pkg.NixNames[0]))
	} else {
		b.WriteString(" (no nix mapping)")
	}
	b.WriteString(fmt.Sprintf(" [%s]", printableDecision(pkg.Decision)))
	if pkg.Version != "" {
		b.WriteString(fmt.Sprintf(" version `%s`", pkg.Version))
	}
	if pkg.Source != "" {
		b.WriteString(fmt.Sprintf(" source `%s`", pkg.Source))
	}
	b.WriteString("\n")
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
		if service.Decision == model.DecisionConfirmed && service.Manager == "systemd" {
			b.WriteString("  # Generated hint: ")
			b.WriteString(comment(fmt.Sprintf("systemd.services.%s.enable = true;", quote(serviceNameAttr(service.Name)))))
			b.WriteString("\n")
		}
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

func renderFilesystemReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Filesystem migration findings\n\n")
	sections := []struct {
		title      string
		categories []string
	}{
		{"Executable files", []string{"executable"}},
		{"Scripts", []string{"script"}},
		{"Service and desktop entries", []string{"service", "desktop-entry"}},
		{"Config files", []string{"config"}},
		{"Secret-risk files", []string{"secret"}},
		{"Other findings", []string{}},
	}
	written := map[string]bool{}
	for _, section := range sections {
		findings := filesystemFindingsByCategory(report, section.categories, written)
		if len(findings) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, finding := range findings {
			b.WriteString(fileFindingLine(finding))
			written[finding.Path] = true
		}
		b.WriteString("\n")
	}
	stateful := statefulFindings(report)
	if len(stateful) > 0 {
		b.WriteString("## Stateful data\n\n")
		for _, finding := range stateful {
			b.WriteString(fileFindingLine(finding))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderUsersReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# User account findings\n\n")
	primary := primaryUser(report)
	b.WriteString(fmt.Sprintf("- Primary Home Manager user: `%s` home `%s`\n\n", primary.Name, primary.Home))
	sections := []struct {
		title string
		users []model.User
	}{
		{"Human users", humanUsers(report)},
		{"Privileged and group-sensitive users", privilegedUsers(report)},
		{"System users", systemUsers(report)},
	}
	for _, section := range sections {
		if len(section.users) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, user := range section.users {
			b.WriteString(userLine(user))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderPackageSourcesReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Package source findings\n\n")
	aptPackages := packagesByManager(report, "apt")
	if len(aptPackages) > 0 {
		b.WriteString("## Apt packages\n\n")
		for _, pkg := range aptPackages {
			b.WriteString(packageLine(pkg))
		}
		b.WriteString("\n")
	}
	sections := []struct {
		title string
		kinds []string
	}{
		{"Apt repositories", []string{"apt-source"}},
		{"Apt keyrings", []string{"apt-keyring"}},
		{"Apt preferences", []string{"apt-preference"}},
		{"Apt configuration", []string{"apt-config"}},
	}
	for _, section := range sections {
		items := packageSourceItemsByKind(report, section.kinds...)
		if len(items) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Source != "" {
				b.WriteString(fmt.Sprintf("\n  - source: `%s`", item.Source))
			}
			if item.Reason != "" {
				b.WriteString(fmt.Sprintf("\n  - reason: %s", item.Reason))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	altPackages := packagesByManager(report, "snap", "flatpak", "appimage", "homebrew")
	if len(altPackages) > 0 {
		b.WriteString("## Alternative package ecosystems\n\n")
		for _, pkg := range altPackages {
			b.WriteString(packageLine(pkg))
		}
	}
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

func renderContainersReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Container findings\n\n")
	runtimeContainers := runtimeContainers(report)
	if len(runtimeContainers) > 0 {
		b.WriteString("## Runtime containers\n\n")
		for _, container := range runtimeContainers {
			b.WriteString(fmt.Sprintf("- %s [%s]\n", containerSummary(container), printableDecision(container.Decision)))
			if container.Digest != "" {
				b.WriteString(fmt.Sprintf("  - digest: `%s`\n", container.Digest))
			}
			if len(container.Ports) > 0 {
				b.WriteString(fmt.Sprintf("  - ports: %s\n", strings.Join(container.Ports, ", ")))
			}
			if len(container.Mounts) > 0 {
				b.WriteString(fmt.Sprintf("  - mounts: %s\n", strings.Join(container.Mounts, ", ")))
			}
			if len(container.Env) > 0 {
				b.WriteString(fmt.Sprintf("  - env keys: %s\n", strings.Join(envKeys(container.Env), ", ")))
			}
		}
		b.WriteString("\n")
	}
	composeFiles := composeContainers(report)
	if len(composeFiles) > 0 {
		b.WriteString("## Compose files\n\n")
		for _, container := range composeFiles {
			b.WriteString(fmt.Sprintf("- `%s` [%s]\n", container.Compose, printableDecision(container.Decision)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderGitSourcesReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Git source findings\n\n")
	for _, source := range gitSources(report) {
		b.WriteString(fmt.Sprintf("- `%s` [%s]\n", source.Path, printableDecision(source.Decision)))
		if source.Remote != "" {
			b.WriteString(fmt.Sprintf("  - remote: `%s`\n", source.Remote))
		}
		if source.Commit != "" {
			b.WriteString(fmt.Sprintf("  - commit: `%s`\n", source.Commit))
		}
		if source.Dirty {
			b.WriteString("  - dirty: true\n")
		}
		if len(source.Build) > 0 {
			b.WriteString(fmt.Sprintf("  - build hints: %s\n", strings.Join(source.Build, ", ")))
		}
	}
	return b.String()
}

func renderLanguagesReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Language ecosystem findings\n\n")
	sections := []struct {
		title string
		pkgs  []model.Package
	}{
		{"Node global packages", report.Languages.NPM},
		{"Conda environments", report.Languages.Conda},
		{"Cargo-installed binaries", report.Languages.Cargo},
		{"Go-installed binaries", report.Languages.Go},
		{"Ruby gems", report.Languages.Gem},
	}
	for _, section := range sections {
		pkgs := languagePackages(section.pkgs)
		if len(pkgs) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, pkg := range pkgs {
			b.WriteString(languagePackageLine(pkg, ""))
		}
		b.WriteString("\n")
	}
	if len(report.Languages.Python) > 0 {
		b.WriteString("## Python environments\n\n")
		for _, env := range report.Languages.Python {
			b.WriteString(fmt.Sprintf("- `%s` %s\n", env.Path, env.Kind))
			for _, pkg := range languagePackages(env.Packages) {
				b.WriteString("  ")
				b.WriteString(languagePackageLine(pkg, env.Path))
			}
		}
		b.WriteString("\n")
	}
	if len(report.Languages.VMs) > 0 {
		b.WriteString("## Version managers\n\n")
		vms := append([]model.VersionTool(nil), report.Languages.VMs...)
		sort.Slice(vms, func(i, j int) bool { return vms[i].Path < vms[j].Path })
		for _, vm := range vms {
			b.WriteString(fmt.Sprintf("- `%s` at `%s`\n", vm.Name, vm.Path))
		}
		b.WriteString("\n")
	}
	items := languageProjectItems(report)
	if len(items) > 0 {
		b.WriteString("## Project language files\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Reason != "" {
				b.WriteString(": ")
				b.WriteString(item.Reason)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func renderSystemConfigReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# System configuration findings\n\n")
	sections := []struct {
		title string
		match func(model.Item) bool
	}{
		{"Network", func(item model.Item) bool { return strings.Contains(item.Reason, "network") }},
		{"Firewall", func(item model.Item) bool { return strings.Contains(item.Reason, "firewall") }},
		{"Web servers", func(item model.Item) bool { return strings.Contains(item.Reason, "web server") }},
		{"Kernel and devices", func(item model.Item) bool {
			return strings.Contains(item.Reason, "kernel") || strings.Contains(item.Reason, "device")
		}},
		{"Core system", func(item model.Item) bool { return item.Kind == "os-config" }},
	}
	written := map[string]bool{}
	for _, section := range sections {
		items := systemConfigItemsByMatch(report, section.match, written)
		if len(items) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Reason != "" {
				b.WriteString(": ")
				b.WriteString(item.Reason)
			}
			b.WriteString("\n")
			for _, detail := range itemDetails(item) {
				b.WriteString("  - ")
				b.WriteString(detail)
				b.WriteString("\n")
			}
			written[item.Path] = true
		}
		b.WriteString("\n")
	}
	if len(systemServices(report)) > 0 {
		b.WriteString("## Services\n\n")
		for _, service := range systemServices(report) {
			b.WriteString(fmt.Sprintf("- `%s` %s `%s` [%s]", service.Name, service.Manager, service.Path, printableDecision(service.Decision)))
			if service.Description != "" {
				b.WriteString(fmt.Sprintf(": %s", service.Description))
			}
			b.WriteString("\n")
			for _, detail := range serviceDetails(service) {
				b.WriteString("  - ")
				b.WriteString(detail)
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func serviceDetails(service model.Service) []string {
	var details []string
	if service.User != "" {
		details = append(details, fmt.Sprintf("user `%s`", service.User))
	}
	if service.WorkingDirectory != "" {
		details = append(details, fmt.Sprintf("working directory `%s`", service.WorkingDirectory))
	}
	if service.ExecStart != "" {
		details = append(details, fmt.Sprintf("exec `%s`", redactSecretLikeText(service.ExecStart)))
	}
	if len(service.EnvironmentFiles) > 0 {
		details = append(details, fmt.Sprintf("environment files `%s`", strings.Join(service.EnvironmentFiles, "`, `")))
	}
	if len(service.WantedBy) > 0 {
		details = append(details, fmt.Sprintf("wanted by `%s`", strings.Join(service.WantedBy, "`, `")))
	}
	if service.Schedule != "" {
		details = append(details, fmt.Sprintf("schedule `%s`", service.Schedule))
	}
	return details
}

func itemDetails(item model.Item) []string {
	if len(item.Details) == 0 {
		return nil
	}
	keys := make([]string, 0, len(item.Details))
	for key := range item.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	details := make([]string, 0, len(keys))
	for _, key := range keys {
		value := redactSecretLikeText(item.Details[key])
		if value == "" {
			continue
		}
		details = append(details, fmt.Sprintf("%s `%s`", key, value))
	}
	return details
}

func renderDevOpsConfigReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# DevOps configuration findings\n\n")
	sections := []struct {
		title string
		match func(model.Item) bool
	}{
		{"Kubernetes", func(item model.Item) bool { return strings.Contains(item.Path, "/.kube/") }},
		{"Docker", func(item model.Item) bool { return strings.Contains(item.Path, "/.docker/") }},
		{"Helm", func(item model.Item) bool { return strings.Contains(item.Path, "/helm/") }},
		{"Terraform", func(item model.Item) bool { return strings.Contains(item.Path, ".terraformrc") }},
		{"AWS", func(item model.Item) bool { return strings.Contains(item.Path, "/.aws/") }},
		{"GCP", func(item model.Item) bool { return strings.Contains(item.Path, "/gcloud/") }},
		{"Azure", func(item model.Item) bool { return strings.Contains(item.Path, "/.azure/") }},
		{"Other", func(item model.Item) bool { return item.Kind == "devops-config" }},
	}
	written := map[string]bool{}
	for _, section := range sections {
		items := devOpsConfigItemsByMatch(report, section.match, written)
		if len(items) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Reason != "" {
				b.WriteString(": ")
				b.WriteString(item.Reason)
			}
			b.WriteString("\n")
			written[item.Path] = true
		}
		b.WriteString("\n")
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
	writeDesktopItemSection(&b, "Browser profiles", browserProfileItems(report))
	writeDesktopItemSection(&b, "Browser extensions", browserExtensionItems(report))
	writeDesktopItemSection(&b, "Editor profiles", editorProfileItems(report))
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

func writeDesktopItemSection(b *strings.Builder, title string, items []model.Item) {
	if len(items) == 0 {
		return
	}
	b.WriteString("\n## ")
	b.WriteString(title)
	b.WriteString("\n\n")
	for _, item := range items {
		b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
		if item.Reason != "" {
			b.WriteString(": ")
			b.WriteString(item.Reason)
		}
		b.WriteString("\n")
	}
}

func renderUserConfigReport(report model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# User configuration findings\n\n")
	sections := []struct {
		title string
		kinds []string
	}{
		{"Shell configuration", []string{"shell-config"}},
		{"Shell plugins", []string{"shell-plugin"}},
		{"User-local executables", []string{"user-bin"}},
		{"User tool configuration", []string{"user-config"}},
		{"Direnv", []string{"direnv"}},
	}
	for _, section := range sections {
		items := userConfigItemsByKind(report, section.kinds...)
		if len(items) == 0 {
			continue
		}
		b.WriteString("## ")
		b.WriteString(section.title)
		b.WriteString("\n\n")
		for _, item := range items {
			b.WriteString(fmt.Sprintf("- `%s` %s [%s]", item.Path, item.Name, printableDecision(item.Decision)))
			if item.Reason != "" {
				b.WriteString(": ")
				b.WriteString(item.Reason)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func todoComments(report model.ScanReport) []string {
	var lines []string
	for _, item := range report.Items {
		if includeDecision(item.Decision) && isHomeTODOItem(item) {
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

func nixUsers(report model.ScanReport) []model.User {
	var users []model.User
	for _, user := range report.Users {
		if user.System || user.Name == "root" || !strings.HasPrefix(user.Home, "/home/") {
			continue
		}
		users = append(users, user)
	}
	sortUsers(users)
	return users
}

func generatedHostShells(report model.ScanReport) []string {
	seen := map[string]bool{}
	for _, user := range nixUsers(report) {
		switch nixShellPackage(user.Shell) {
		case "pkgs.zsh":
			seen["zsh"] = true
		case "pkgs.fish":
			seen["fish"] = true
		}
	}
	order := []string{"zsh", "fish"}
	var shells []string
	for _, shell := range order {
		if seen[shell] {
			shells = append(shells, shell)
		}
	}
	return shells
}

func generatedHomePrograms(report model.ScanReport) []string {
	user := primaryUser(report)
	programs := map[string]bool{}
	for _, item := range report.Items {
		if item.Decision != model.DecisionConfirmed || !strings.HasPrefix(item.Path, user.Home+"/") {
			continue
		}
		switch {
		case item.Kind == "shell-config" && shellProgramFromPath(item.Path) != "":
			programs[shellProgramFromPath(item.Path)] = true
		case item.Kind == "user-config" && strings.HasSuffix(item.Path, "/.gitconfig"):
			programs["git"] = true
		case item.Kind == "user-config" && strings.HasSuffix(item.Path, "/.tmux.conf"):
			programs["tmux"] = true
		case item.Kind == "user-config" && strings.HasSuffix(item.Path, "/.config/starship.toml"):
			programs["starship"] = true
		}
	}
	order := []string{"bash", "zsh", "fish", "git", "tmux", "starship"}
	var out []string
	for _, program := range order {
		if programs[program] {
			out = append(out, program)
		}
	}
	return out
}

func nixUserGroups(user model.User) []string {
	allowed := []string{"sudo", "wheel", "docker", "podman", "audio", "video", "input", "plugdev", "dialout"}
	var groups []string
	for _, group := range user.Groups {
		if containsString(allowed, group) {
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	return groups
}

func nixStringList(values []string, indent int) string {
	if len(values) == 0 {
		return "[ ]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	prefix := strings.Repeat(" ", indent)
	for _, value := range values {
		b.WriteString(prefix)
		b.WriteString("  ")
		b.WriteString(quote(value))
		b.WriteString("\n")
	}
	b.WriteString(prefix)
	b.WriteString("]")
	return b.String()
}

func nixShellPackage(shell string) string {
	switch shell {
	case "/bin/zsh", "/usr/bin/zsh":
		return "pkgs.zsh"
	case "/bin/fish", "/usr/bin/fish":
		return "pkgs.fish"
	default:
		return ""
	}
}

func shellProgramFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, "/.bashrc") || strings.HasSuffix(path, "/.bash_profile") || strings.HasSuffix(path, "/.profile"):
		return "bash"
	case strings.HasSuffix(path, "/.zshrc") || strings.HasSuffix(path, "/.zprofile"):
		return "zsh"
	case strings.Contains(path, "/.config/fish/"):
		return "fish"
	default:
		return ""
	}
}

func serviceNameAttr(name string) string {
	name = strings.TrimSuffix(name, ".service")
	return name
}

func redactSecretLikeText(text string) string {
	var out []string
	for _, field := range strings.Fields(text) {
		lower := strings.ToLower(field)
		switch {
		case strings.Contains(lower, "password="),
			strings.Contains(lower, "passwd="),
			strings.Contains(lower, "token="),
			strings.Contains(lower, "secret="),
			strings.Contains(lower, "api_key="),
			strings.Contains(lower, "apikey="),
			strings.Contains(lower, "access_key="):
			if key, _, ok := strings.Cut(field, "="); ok {
				out = append(out, key+"=<redacted>")
			} else {
				out = append(out, "<redacted>")
			}
		default:
			out = append(out, field)
		}
	}
	return strings.Join(out, " ")
}

func humanUsers(report model.ScanReport) []model.User {
	var users []model.User
	for _, user := range report.Users {
		if !user.System && user.Name != "root" {
			users = append(users, user)
		}
	}
	sortUsers(users)
	return users
}

func systemUsers(report model.ScanReport) []model.User {
	var users []model.User
	for _, user := range report.Users {
		if user.System || user.Name == "root" {
			users = append(users, user)
		}
	}
	sortUsers(users)
	return users
}

func privilegedUsers(report model.ScanReport) []model.User {
	var users []model.User
	for _, user := range report.Users {
		if hasSensitiveGroup(user) {
			users = append(users, user)
		}
	}
	sortUsers(users)
	return users
}

func sortUsers(users []model.User) {
	sort.Slice(users, func(i, j int) bool {
		if users[i].Name != users[j].Name {
			return users[i].Name < users[j].Name
		}
		return users[i].UID < users[j].UID
	})
}

func hasSensitiveGroup(user model.User) bool {
	for _, group := range user.Groups {
		if containsString([]string{"sudo", "wheel", "admin", "docker", "podman", "audio", "video", "input", "plugdev", "dialout"}, group) {
			return true
		}
	}
	return false
}

func userLine(user model.User) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("- `%s` uid `%s` gid `%s` home `%s` shell `%s`", user.Name, user.UID, user.GID, user.Home, user.Shell))
	if len(user.Groups) > 0 {
		b.WriteString(fmt.Sprintf(" groups `%s`", strings.Join(user.Groups, ", ")))
	}
	if user.System {
		b.WriteString(" system")
	}
	b.WriteString("\n")
	return b.String()
}

func packagesByManager(report model.ScanReport, managers ...string) []model.Package {
	var packages []model.Package
	for _, pkg := range report.Packages {
		if reportDecision(pkg.Decision) && containsString(managers, pkg.Manager) {
			packages = append(packages, pkg)
		}
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Manager != packages[j].Manager {
			return packages[i].Manager < packages[j].Manager
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Source < packages[j].Source
	})
	return packages
}

func packageSourceItems(report model.ScanReport) []model.Item {
	return packageSourceItemsByKind(report, "apt-source", "apt-keyring", "apt-preference", "apt-config")
}

func packageSourceItemsByKind(report model.ScanReport, kinds ...string) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && containsString(kinds, item.Kind) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func filesystemFindingsByCategory(report model.ScanReport, categories []string, written map[string]bool) []model.FileFinding {
	var findings []model.FileFinding
	for _, finding := range filesystemFindings(report) {
		if written[finding.Path] {
			continue
		}
		if len(categories) == 0 || containsString(categories, finding.Category) {
			findings = append(findings, finding)
		}
	}
	return findings
}

func filesystemFindings(report model.ScanReport) []model.FileFinding {
	var findings []model.FileFinding
	for _, finding := range report.FilesystemDiff {
		if reportDecision(finding.Decision) {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings
}

func statefulFindings(report model.ScanReport) []model.FileFinding {
	var findings []model.FileFinding
	for _, finding := range report.StatefulData {
		if reportDecision(finding.Decision) {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings
}

func fileFindingLine(finding model.FileFinding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("- `%s` %s/%s [%s]", finding.Path, finding.Category, finding.Type, printableDecision(finding.Decision)))
	if finding.Mode != "" {
		b.WriteString(fmt.Sprintf(" mode `%s`", finding.Mode))
	}
	if finding.Size > 0 {
		b.WriteString(fmt.Sprintf(" size `%d`", finding.Size))
	}
	if finding.SHA256 != "" {
		b.WriteString(fmt.Sprintf(" sha256 `%s`", finding.SHA256))
	}
	if finding.SecretRisk {
		b.WriteString(" secret-risk")
	}
	if finding.Reason != "" {
		b.WriteString(": ")
		b.WriteString(finding.Reason)
	}
	b.WriteString("\n")
	return b.String()
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

func browserProfileItems(report model.ScanReport) []model.Item {
	return desktopItemsByKind(report, "browser-profile")
}

func browserExtensionItems(report model.ScanReport) []model.Item {
	return desktopItemsByKind(report, "browser-extension")
}

func editorProfileItems(report model.ScanReport) []model.Item {
	return desktopItemsByKind(report, "editor-profile")
}

func desktopItemsByKind(report model.ScanReport, kind string) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && item.Kind == kind {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func systemConfigItems(report model.ScanReport) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && item.Kind == "os-config" {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func systemConfigItemsByMatch(report model.ScanReport, match func(model.Item) bool, written map[string]bool) []model.Item {
	var items []model.Item
	for _, item := range systemConfigItems(report) {
		if !written[item.Path] && match(item) {
			items = append(items, item)
		}
	}
	return items
}

func systemServices(report model.ScanReport) []model.Service {
	var services []model.Service
	for _, service := range report.Services {
		if reportDecision(service.Decision) {
			services = append(services, service)
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Path < services[j].Path })
	return services
}

func runtimeContainers(report model.ScanReport) []model.Container {
	var containers []model.Container
	for _, container := range report.Containers {
		if reportDecision(container.Decision) && container.Runtime != "compose" {
			containers = append(containers, container)
		}
	}
	sort.Slice(containers, func(i, j int) bool {
		return containerSortKey(containers[i]) < containerSortKey(containers[j])
	})
	return containers
}

func composeContainers(report model.ScanReport) []model.Container {
	var containers []model.Container
	for _, container := range report.Containers {
		if reportDecision(container.Decision) && container.Runtime == "compose" {
			containers = append(containers, container)
		}
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Compose < containers[j].Compose })
	return containers
}

func gitSources(report model.ScanReport) []model.GitSource {
	var sources []model.GitSource
	for _, source := range report.GitSources {
		if reportDecision(source.Decision) {
			sources = append(sources, source)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	return sources
}

func languagePackages(pkgs []model.Package) []model.Package {
	var out []model.Package
	for _, pkg := range pkgs {
		if reportDecision(pkg.Decision) {
			out = append(out, pkg)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Manager != out[j].Manager {
			return out[i].Manager < out[j].Manager
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func languageProjectItems(report model.ScanReport) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && item.Kind == "language-project" {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func containerSortKey(container model.Container) string {
	if container.Name != "" {
		return container.Runtime + ":" + container.Name
	}
	return container.Runtime + ":" + container.Image
}

func envKeys(env map[string]string) []string {
	var keys []string
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func devOpsConfigItems(report model.ScanReport) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && item.Kind == "devops-config" {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func devOpsConfigItemsByMatch(report model.ScanReport, match func(model.Item) bool, written map[string]bool) []model.Item {
	var items []model.Item
	for _, item := range devOpsConfigItems(report) {
		if !written[item.Path] && match(item) {
			items = append(items, item)
		}
	}
	return items
}

func userConfigItems(report model.ScanReport) []model.Item {
	return userConfigItemsByKind(report, "user-config", "shell-config", "shell-plugin", "user-bin", "direnv")
}

func userConfigItemsByKind(report model.ScanReport, kinds ...string) []model.Item {
	var items []model.Item
	for _, item := range report.Items {
		if reportDecision(item.Decision) && containsString(kinds, item.Kind) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items
}

func isHomeTODOItem(item model.Item) bool {
	return item.Kind == "user-config" ||
		item.Kind == "shell-config" ||
		item.Kind == "shell-plugin" ||
		item.Kind == "user-bin" ||
		item.Kind == "direnv" ||
		item.Kind == "desktop-config"
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func secretLikeReason(reason string) bool {
	text := strings.ToLower(reason)
	return strings.Contains(text, "credential") ||
		strings.Contains(text, "secret") ||
		strings.Contains(text, "token") ||
		strings.Contains(text, "password")
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
{{ hostShellOptions .Report }}
{{ hostUserOptions .Report }}

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
{{ homeProgramOptions .Report }}

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
