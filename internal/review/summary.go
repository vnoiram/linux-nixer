package review

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type Summary struct {
	Total                     int             `json:"total"`
	Pending                   int             `json:"pending"`
	ProtectedFindings         int             `json:"protectedFindings"`
	UnmappedPackages          int             `json:"unmappedPackages"`
	ManualMigrationNotes      int             `json:"manualMigrationNotes"`
	SecretOrProtectedFindings int             `json:"secretOrProtectedFindings"`
	GeneratedCandidates       int             `json:"generatedCandidates"`
	Decisions                 map[string]int  `json:"decisions"`
	Domains                   []DomainSummary `json:"domains"`
	NixImpact                 NixImpact       `json:"nixImpact"`
}

type DomainSummary struct {
	Domain            string         `json:"domain"`
	Total             int            `json:"total"`
	Pending           int            `json:"pending"`
	ProtectedFindings int            `json:"protectedFindings,omitempty"`
	UnmappedPackages  int            `json:"unmappedPackages,omitempty"`
	MigrationNotes    int            `json:"migrationNotes,omitempty"`
	Decisions         map[string]int `json:"decisions"`
}

type NixImpact struct {
	SystemPackages          int `json:"systemPackages"`
	HomePackages            int `json:"homePackages"`
	Users                   int `json:"users"`
	HostShellPrograms       int `json:"hostShellPrograms"`
	HomePrograms            int `json:"homePrograms"`
	SystemdServices         int `json:"systemdServices"`
	CronJobs                int `json:"cronJobs"`
	ContainerRuntimeEnables int `json:"containerRuntimeEnables"`
	ConfirmedContainers     int `json:"confirmedContainers"`
}

func Summarize(report model.ScanReport) Summary {
	s := Summary{
		Decisions: emptyDecisionCounts(),
		NixImpact: NixImpact{
			SystemPackages:          len(systemPackageNames(report)),
			HomePackages:            len(homePackageNames(report)),
			Users:                   len(humanUsers(report)),
			HostShellPrograms:       len(hostShellPrograms(report)),
			HomePrograms:            len(homePrograms(report)),
			SystemdServices:         confirmedSystemdServices(report),
			CronJobs:                confirmedCronJobs(report),
			ContainerRuntimeEnables: containerRuntimeEnables(report),
			ConfirmedContainers:     confirmedContainers(report),
		},
	}
	s.GeneratedCandidates = generatedCandidates(s.NixImpact)

	addDomain := func(domain string, decisions []model.Decision, protected, unmapped int) {
		if len(decisions) == 0 {
			return
		}
		d := DomainSummary{
			Domain:            domain,
			Total:             len(decisions),
			ProtectedFindings: protected,
			UnmappedPackages:  unmapped,
			Decisions:         emptyDecisionCounts(),
		}
		for _, decision := range decisions {
			key := decisionKey(decision)
			d.Decisions[key]++
			s.Decisions[key]++
			if decision == model.DecisionMigrationNote {
				d.MigrationNotes++
				s.ManualMigrationNotes++
			}
			if isPending(decision) {
				d.Pending++
				s.Pending++
			}
		}
		s.Total += d.Total
		s.ProtectedFindings += protected
		s.UnmappedPackages += unmapped
		s.Domains = append(s.Domains, d)
	}

	addDomain("packages", packageDecisions(report.Packages), 0, unmappedPackages(report.Packages))
	addDomain("language-packages", languagePackageDecisions(report), 0, unmappedLanguagePackages(report))
	addDomain("git-sources", gitSourceDecisions(report.GitSources), 0, 0)
	addDomain("containers", containerDecisions(report.Containers), 0, 0)
	addDomain("services", serviceDecisions(report.Services), 0, 0)
	addDomain("filesystem-findings", fileFindingDecisions(report.FilesystemDiff), protectedFileFindings(report.FilesystemDiff, false), 0)
	addDomain("stateful-data", fileFindingDecisions(report.StatefulData), protectedFileFindings(report.StatefulData, true), 0)
	addDomain("config-items", itemDecisions(report.Items), 0, 0)
	addDomain("desktop-autostart", fileFindingDecisions(report.Desktop.Autostart), protectedFileFindings(report.Desktop.Autostart, false), 0)
	s.SecretOrProtectedFindings = s.ProtectedFindings

	return s
}

func FormatSummaryMarkdown(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Review summary\n\n")
	fmt.Fprintf(&b, "Total findings: %d\n", s.Total)
	fmt.Fprintf(&b, "Pending findings: %d\n", s.Pending)
	fmt.Fprintf(&b, "Protected findings: %d\n\n", s.ProtectedFindings)

	b.WriteString("## Review focus\n\n")
	fmt.Fprintf(&b, "- Nix candidate coverage gaps: %d unmapped packages\n", s.UnmappedPackages)
	fmt.Fprintf(&b, "- Manual migration notes: %d\n", s.ManualMigrationNotes)
	fmt.Fprintf(&b, "- Secret/stateful/protected findings: %d\n", s.SecretOrProtectedFindings)
	fmt.Fprintf(&b, "- Generated Nix candidates: %d\n\n", s.GeneratedCandidates)

	b.WriteString("## Decisions\n\n")
	for _, key := range decisionKeys() {
		fmt.Fprintf(&b, "- %s: %d\n", key, s.Decisions[key])
	}

	b.WriteString("\n## Domains\n\n")
	for _, domain := range s.Domains {
		fmt.Fprintf(&b, "- %s: total=%d pending=%d", domain.Domain, domain.Total, domain.Pending)
		if domain.ProtectedFindings > 0 {
			fmt.Fprintf(&b, " protected=%d", domain.ProtectedFindings)
		}
		if domain.UnmappedPackages > 0 {
			fmt.Fprintf(&b, " unmapped=%d", domain.UnmappedPackages)
		}
		if domain.MigrationNotes > 0 {
			fmt.Fprintf(&b, " migration-notes=%d", domain.MigrationNotes)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Generated Nix impact\n\n")
	fmt.Fprintf(&b, "- system packages: %d\n", s.NixImpact.SystemPackages)
	fmt.Fprintf(&b, "- home packages: %d\n", s.NixImpact.HomePackages)
	fmt.Fprintf(&b, "- users: %d\n", s.NixImpact.Users)
	fmt.Fprintf(&b, "- host shell programs: %d\n", s.NixImpact.HostShellPrograms)
	fmt.Fprintf(&b, "- home programs: %d\n", s.NixImpact.HomePrograms)
	fmt.Fprintf(&b, "- systemd services: %d\n", s.NixImpact.SystemdServices)
	fmt.Fprintf(&b, "- cron jobs: %d\n", s.NixImpact.CronJobs)
	fmt.Fprintf(&b, "- container runtime enables: %d\n", s.NixImpact.ContainerRuntimeEnables)
	fmt.Fprintf(&b, "- confirmed containers: %d\n", s.NixImpact.ConfirmedContainers)
	writeNextActions(&b, s)
	return b.String()
}

// FormatProgressMarkdown renders a Progress comparison as a human-readable
// report showing what changed since a previously exported DecisionSet.
func FormatProgressMarkdown(p Progress) string {
	var b strings.Builder
	b.WriteString("## Migration progress since last snapshot\n\n")
	fmt.Fprintf(&b, "- previously decided: %d\n", p.PreviousDecided)
	fmt.Fprintf(&b, "- currently decided: %d\n", p.CurrentDecided)
	fmt.Fprintf(&b, "- still pending: %d\n", p.StillPending)
	fmt.Fprintf(&b, "- newly decided: %d\n", len(p.NewlyDecided))
	fmt.Fprintf(&b, "- changed: %d\n", len(p.Changed))
	fmt.Fprintf(&b, "- regressed to pending: %d\n", len(p.Regressed))
	fmt.Fprintf(&b, "- no longer present: %d\n", len(p.Removed))

	writeProgressSection(&b, "Newly decided", p.NewlyDecided, func(e ProgressEntry) string {
		return fmt.Sprintf("- %s `%s` -> %s\n", e.Domain, e.Key, e.CurrentDecision)
	})
	writeProgressSection(&b, "Changed", p.Changed, func(e ProgressEntry) string {
		return fmt.Sprintf("- %s `%s`: %s -> %s\n", e.Domain, e.Key, e.PreviousDecision, e.CurrentDecision)
	})
	writeProgressSection(&b, "Regressed to pending", p.Regressed, func(e ProgressEntry) string {
		return fmt.Sprintf("- %s `%s` (was %s)\n", e.Domain, e.Key, e.PreviousDecision)
	})
	writeProgressSection(&b, "No longer present", p.Removed, func(e ProgressEntry) string {
		return fmt.Sprintf("- %s `%s` (was %s)\n", e.Domain, e.Key, e.PreviousDecision)
	})

	return b.String()
}

func writeProgressSection(b *strings.Builder, title string, entries []ProgressEntry, line func(ProgressEntry) string) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "\n### %s\n\n", title)
	for _, e := range entries {
		b.WriteString(line(e))
	}
}

func writeNextActions(b *strings.Builder, s Summary) {
	b.WriteString("\n## Next actions\n\n")
	if s.Pending > 0 {
		fmt.Fprintf(b, "- Resolve %d pending candidate/todo findings with `linux-nixer review --interactive` or a repeatable policy.\n", s.Pending)
	} else {
		b.WriteString("- No pending candidate/todo findings remain.\n")
	}
	if s.UnmappedPackages > 0 {
		fmt.Fprintf(b, "- Decide package, replacement, manual install, or exclusion strategy for %d unmapped packages.\n", s.UnmappedPackages)
	}
	if s.ManualMigrationNotes > 0 {
		fmt.Fprintf(b, "- Review `%s` for %d manual migration notes before switching systems.\n", "reports/migration-checklist.md", s.ManualMigrationNotes)
	}
	if s.SecretOrProtectedFindings > 0 {
		fmt.Fprintf(b, "- Back up or restore %d secret/stateful/protected findings outside generated Nix.\n", s.SecretOrProtectedFindings)
	}
	if s.GeneratedCandidates > 0 {
		fmt.Fprintf(b, "- Review generated Nix output for %d confirmed items before applying it.\n", s.GeneratedCandidates)
	}
}

func emptyDecisionCounts() map[string]int {
	counts := map[string]int{}
	for _, key := range decisionKeys() {
		counts[key] = 0
	}
	return counts
}

func decisionKeys() []string {
	return []string{
		string(model.DecisionConfirmed),
		string(model.DecisionCandidate),
		string(model.DecisionTODO),
		string(model.DecisionMigrationNote),
		string(model.DecisionExcluded),
		"unset",
	}
}

func decisionKey(decision model.Decision) string {
	if decision == "" {
		return "unset"
	}
	return string(decision)
}

func isPending(decision model.Decision) bool {
	return decision == model.DecisionCandidate || decision == model.DecisionTODO
}

func packageDecisions(pkgs []model.Package) []model.Decision {
	decisions := make([]model.Decision, 0, len(pkgs))
	for _, pkg := range pkgs {
		decisions = append(decisions, pkg.Decision)
	}
	return decisions
}

func unmappedPackages(pkgs []model.Package) int {
	count := 0
	for _, pkg := range pkgs {
		if reportableUnmappedPackage(pkg) {
			count++
		}
	}
	return count
}

func languagePackageDecisions(report model.ScanReport) []model.Decision {
	var decisions []model.Decision
	for _, pkgs := range [][]model.Package{report.Languages.NPM, report.Languages.Conda, report.Languages.Cargo, report.Languages.Gem, report.Languages.Go} {
		decisions = append(decisions, packageDecisions(pkgs)...)
	}
	for _, env := range report.Languages.Python {
		decisions = append(decisions, packageDecisions(env.Packages)...)
	}
	return decisions
}

func unmappedLanguagePackages(report model.ScanReport) int {
	count := 0
	for _, pkgs := range [][]model.Package{report.Languages.NPM, report.Languages.Conda, report.Languages.Cargo, report.Languages.Gem, report.Languages.Go} {
		count += unmappedPackages(pkgs)
	}
	for _, env := range report.Languages.Python {
		count += unmappedPackages(env.Packages)
	}
	return count
}

func reportableUnmappedPackage(pkg model.Package) bool {
	return pkg.Decision != model.DecisionExcluded && pkg.Decision != model.DecisionMigrationNote && len(pkg.NixNames) == 0
}

func gitSourceDecisions(items []model.GitSource) []model.Decision {
	decisions := make([]model.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, item.Decision)
	}
	return decisions
}

func containerDecisions(items []model.Container) []model.Decision {
	decisions := make([]model.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, item.Decision)
	}
	return decisions
}

func serviceDecisions(items []model.Service) []model.Decision {
	decisions := make([]model.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, item.Decision)
	}
	return decisions
}

func fileFindingDecisions(items []model.FileFinding) []model.Decision {
	decisions := make([]model.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, item.Decision)
	}
	return decisions
}

func itemDecisions(items []model.Item) []model.Decision {
	decisions := make([]model.Decision, 0, len(items))
	for _, item := range items {
		decisions = append(decisions, item.Decision)
	}
	return decisions
}

func protectedFileFindings(items []model.FileFinding, force bool) int {
	count := 0
	for _, item := range items {
		if force || item.SecretRisk {
			count++
		}
	}
	return count
}

func generatedCandidates(impact NixImpact) int {
	return impact.SystemPackages +
		impact.HomePackages +
		impact.Users +
		impact.HostShellPrograms +
		impact.HomePrograms +
		impact.SystemdServices +
		impact.CronJobs +
		impact.ContainerRuntimeEnables +
		impact.ConfirmedContainers
}

func systemPackageNames(report model.ScanReport) []string {
	seen := map[string]bool{}
	var names []string
	for _, pkg := range report.Packages {
		if pkg.Decision != model.DecisionConfirmed || len(pkg.NixNames) == 0 {
			continue
		}
		name := pkg.NixNames[0]
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
		name := pkg.NixNames[0]
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

func humanUsers(report model.ScanReport) []model.User {
	var users []model.User
	for _, user := range report.Users {
		if user.System || user.Name == "root" || !strings.HasPrefix(user.Home, "/home/") {
			continue
		}
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users
}

func hostShellPrograms(report model.ScanReport) []string {
	seen := map[string]bool{}
	for _, user := range humanUsers(report) {
		switch {
		case strings.HasSuffix(user.Shell, "/zsh"):
			seen["zsh"] = true
		case strings.HasSuffix(user.Shell, "/fish"):
			seen["fish"] = true
		}
	}
	order := []string{"zsh", "fish"}
	var programs []string
	for _, program := range order {
		if seen[program] {
			programs = append(programs, program)
		}
	}
	return programs
}

func homePrograms(report model.ScanReport) []string {
	user := primaryUser(report)
	programs := map[string]bool{}
	for _, item := range report.Items {
		if item.Decision != model.DecisionConfirmed || !strings.HasPrefix(item.Path, user.Home+"/") {
			continue
		}
		switch {
		case item.Kind == "shell-config" && strings.HasSuffix(item.Path, "/.bashrc"):
			programs["bash"] = true
		case item.Kind == "shell-config" && strings.HasSuffix(item.Path, "/.zshrc"):
			programs["zsh"] = true
		case item.Kind == "shell-config" && strings.HasSuffix(item.Path, "/.config/fish/config.fish"):
			programs["fish"] = true
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

func primaryUser(report model.ScanReport) model.User {
	for _, user := range report.Users {
		if !user.System && user.Name != "root" && strings.HasPrefix(user.Home, "/home/") {
			return user
		}
	}
	return model.User{Name: "generated", Home: "/home/generated"}
}

func confirmedSystemdServices(report model.ScanReport) int {
	count := 0
	for _, service := range report.Services {
		if renderableSystemdService(service) {
			count++
		}
	}
	return count
}

func renderableSystemdService(service model.Service) bool {
	return service.Decision == model.DecisionConfirmed &&
		service.Manager == "systemd" &&
		!strings.HasSuffix(service.Name, ".timer") &&
		service.ExecStart != "" &&
		!secretLikeText(service.ExecStart) &&
		len(service.EnvironmentFiles) == 0
}

func confirmedCronJobs(report model.ScanReport) int {
	count := 0
	for _, service := range report.Services {
		if renderableCronJob(service) {
			count++
		}
	}
	return count
}

func renderableCronJob(service model.Service) bool {
	return service.Decision == model.DecisionConfirmed &&
		service.Manager == "cron" &&
		service.Schedule != "" &&
		service.User != "" &&
		service.ExecStart != "" &&
		!secretLikeText(service.ExecStart)
}

func secretLikeText(text string) bool {
	return redactSecretLikeText(text) != text
}

func containerRuntimeEnables(report model.ScanReport) int {
	docker := false
	podman := false
	for _, container := range report.Containers {
		if container.Decision != model.DecisionConfirmed {
			continue
		}
		if container.Runtime == "docker" || container.Runtime == "compose" {
			docker = true
		}
		if container.Runtime == "podman" {
			podman = true
		}
	}
	count := 0
	if docker {
		count++
	}
	if podman {
		count++
	}
	return count
}

func confirmedContainers(report model.ScanReport) int {
	count := 0
	for _, container := range report.Containers {
		if renderableContainer(container) {
			count++
		}
	}
	return count
}

func renderableContainer(c model.Container) bool {
	return c.Decision == model.DecisionConfirmed && c.Runtime != "compose" && c.Name != "" && c.Image != ""
}
