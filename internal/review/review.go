package review

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type Options struct {
	AutoSafe            bool
	ConfirmKinds        []string
	ExcludeKinds        []string
	TODOKinds           []string
	MigrationNoteKinds  []string
	ConfirmManagers     []string
	ExcludePathPrefixes []string
	PendingOnly         bool
}

func Apply(report model.ScanReport, opts Options) model.ScanReport {
	report = applyDecisions(report, opts)
	report.Warnings = append(report.Warnings, model.Warning{
		Source:  "review",
		Message: "review decisions applied non-interactively; use generated reports before applying Nix output",
	})
	return report
}

func Interactive(in io.Reader, out io.Writer, report model.ScanReport, opts Options) model.ScanReport {
	report = applyDecisions(report, opts)
	session := interactiveSession{in: bufio.NewScanner(in), out: out, quit: false, pendingOnly: opts.PendingOnly}
	session.reviewPackages("packages", report.Packages, func(i int, decision model.Decision) { report.Packages[i].Decision = decision })
	session.reviewPackages("npm", report.Languages.NPM, func(i int, decision model.Decision) { report.Languages.NPM[i].Decision = decision })
	session.reviewPackages("conda", report.Languages.Conda, func(i int, decision model.Decision) { report.Languages.Conda[i].Decision = decision })
	session.reviewPackages("cargo", report.Languages.Cargo, func(i int, decision model.Decision) { report.Languages.Cargo[i].Decision = decision })
	session.reviewPackages("gem", report.Languages.Gem, func(i int, decision model.Decision) { report.Languages.Gem[i].Decision = decision })
	session.reviewPackages("go", report.Languages.Go, func(i int, decision model.Decision) { report.Languages.Go[i].Decision = decision })
	for envIndex := range report.Languages.Python {
		env := &report.Languages.Python[envIndex]
		session.reviewPackages("python "+env.Kind+" "+env.Path, env.Packages, func(i int, decision model.Decision) { env.Packages[i].Decision = decision })
	}
	session.reviewGitSources(report.GitSources, func(i int, decision model.Decision) { report.GitSources[i].Decision = decision })
	session.reviewContainers(report.Containers, func(i int, decision model.Decision) { report.Containers[i].Decision = decision })
	session.reviewServices(report.Services, func(i int, decision model.Decision) { report.Services[i].Decision = decision })
	session.reviewFiles("filesystem findings", report.FilesystemDiff, false, func(i int, decision model.Decision) { report.FilesystemDiff[i].Decision = decision })
	session.reviewFiles("stateful data", report.StatefulData, true, func(i int, decision model.Decision) { report.StatefulData[i].Decision = decision })
	session.reviewItems(report.Items, func(i int, decision model.Decision) { report.Items[i].Decision = decision })
	report.Warnings = append(report.Warnings, model.Warning{
		Source:  "review",
		Message: "interactive review decisions applied; review generated reports before applying Nix output",
	})
	return report
}

func applyDecisions(report model.ScanReport, opts Options) model.ScanReport {
	for i := range report.Packages {
		report.Packages[i].Decision = decidePackage(report.Packages[i], opts)
	}
	applyLanguagePackages(&report.Languages.NPM, opts)
	applyLanguagePackages(&report.Languages.Conda, opts)
	applyLanguagePackages(&report.Languages.Cargo, opts)
	applyLanguagePackages(&report.Languages.Gem, opts)
	applyLanguagePackages(&report.Languages.Go, opts)
	for i := range report.Languages.Python {
		for j := range report.Languages.Python[i].Packages {
			report.Languages.Python[i].Packages[j].Decision = decidePackage(report.Languages.Python[i].Packages[j], opts)
		}
	}
	for i := range report.GitSources {
		report.GitSources[i].Decision = decideFinding("git-source", report.GitSources[i].Path, report.GitSources[i].Decision, false, opts)
	}
	for i := range report.Containers {
		path := report.Containers[i].Compose
		if path == "" {
			path = report.Containers[i].Name
		}
		report.Containers[i].Decision = decideFinding("container", path, report.Containers[i].Decision, false, opts)
	}
	for i := range report.Services {
		report.Services[i].Decision = decideFinding("service", report.Services[i].Path, report.Services[i].Decision, false, opts)
	}
	for i := range report.FilesystemDiff {
		report.FilesystemDiff[i].Decision = decideFinding(report.FilesystemDiff[i].Category, report.FilesystemDiff[i].Path, report.FilesystemDiff[i].Decision, report.FilesystemDiff[i].SecretRisk, opts)
	}
	for i := range report.StatefulData {
		report.StatefulData[i].Decision = model.DecisionMigrationNote
	}
	for i := range report.Items {
		report.Items[i].Decision = decideFinding(report.Items[i].Kind, report.Items[i].Path, report.Items[i].Decision, false, opts)
	}
	return report
}

type interactiveSession struct {
	in          *bufio.Scanner
	out         io.Writer
	quit        bool
	skipSection bool
	pendingOnly bool
}

func (s *interactiveSession) shouldPrompt(decision model.Decision) bool {
	return !s.pendingOnly || decision == model.DecisionCandidate
}

func (s *interactiveSession) reviewPackages(section string, pkgs []model.Package, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, pkg := range pkgs {
		if s.shouldPrompt(pkg.Decision) {
			total++
		}
	}
	shown := 0
	for i, pkg := range pkgs {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(pkg.Decision) {
			continue
		}
		shown++
		s.reviewDecision(section, shown, total, packageSummary(pkg), packageNotes(pkg), pkg.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewGitSources(items []model.GitSource, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, item := range items {
		if s.shouldPrompt(item.Decision) {
			total++
		}
	}
	shown := 0
	for i, item := range items {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(item.Decision) {
			continue
		}
		shown++
		s.reviewDecision("git sources", shown, total, fmt.Sprintf("%s remote=%s commit=%s", item.Path, item.Remote, item.Commit), gitSourceNotes(item), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewContainers(items []model.Container, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, item := range items {
		if s.shouldPrompt(item.Decision) {
			total++
		}
	}
	shown := 0
	for i, item := range items {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(item.Decision) {
			continue
		}
		shown++
		name := item.Name
		if name == "" {
			name = item.Compose
		}
		s.reviewDecision("containers", shown, total, fmt.Sprintf("%s %s image=%s", item.Runtime, name, item.Image), containerNotes(item), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewServices(items []model.Service, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, item := range items {
		if s.shouldPrompt(item.Decision) {
			total++
		}
	}
	shown := 0
	for i, item := range items {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(item.Decision) {
			continue
		}
		shown++
		s.reviewDecision("services", shown, total, fmt.Sprintf("%s %s %s", item.Manager, item.Name, item.Path), serviceNotes(item), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewFiles(section string, items []model.FileFinding, forceMigrationNote bool, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, item := range items {
		if s.shouldPrompt(item.Decision) {
			total++
		}
	}
	shown := 0
	for i, item := range items {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(item.Decision) {
			continue
		}
		shown++
		protected := item.SecretRisk || forceMigrationNote
		s.reviewDecision(section, shown, total, fmt.Sprintf("%s %s %s", item.Category, item.Path, item.Reason), fileFindingNotes(item, protected), item.Decision, protected, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewItems(items []model.Item, set func(int, model.Decision)) {
	s.skipSection = false
	total := 0
	for _, item := range items {
		if s.shouldPrompt(item.Decision) {
			total++
		}
	}
	shown := 0
	for i, item := range items {
		if s.quit || s.skipSection {
			return
		}
		if !s.shouldPrompt(item.Decision) {
			continue
		}
		shown++
		s.reviewDecision("config/items", shown, total, fmt.Sprintf("%s %s %s", item.Kind, item.Path, item.Reason), itemNotes(item), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewDecision(section string, index, total int, summary string, notes []string, current model.Decision, protected bool, set func(model.Decision)) {
	if current == "" {
		current = model.DecisionCandidate
	}
	fmt.Fprintf(s.out, "\n[%s #%d/%d]\n%s\ncurrent: %s\n", section, index, total, summary, current)
	for _, note := range notes {
		if note != "" {
			fmt.Fprintf(s.out, "%s\n", note)
		}
	}
	fmt.Fprint(s.out, "choose c=confirmed k=candidate t=todo m=migration-note x=excluded s=skip n=skip-section q=quit: ")
	if !s.in.Scan() {
		s.quit = true
		return
	}
	choice := strings.TrimSpace(strings.ToLower(s.in.Text()))
	if choice == "q" {
		s.quit = true
		return
	}
	if choice == "n" {
		s.skipSection = true
		return
	}
	decision, ok := choiceDecision(choice)
	if !ok || choice == "s" || choice == "" {
		return
	}
	if protected && decision == model.DecisionConfirmed {
		fmt.Fprintln(s.out, "protected finding cannot be confirmed; keeping migration-note")
		set(model.DecisionMigrationNote)
		return
	}
	set(decision)
}

func choiceDecision(choice string) (model.Decision, bool) {
	switch choice {
	case "c":
		return model.DecisionConfirmed, true
	case "k":
		return model.DecisionCandidate, true
	case "t":
		return model.DecisionTODO, true
	case "m":
		return model.DecisionMigrationNote, true
	case "x":
		return model.DecisionExcluded, true
	case "s", "":
		return "", true
	default:
		return "", false
	}
}

func packageSummary(pkg model.Package) string {
	summary := fmt.Sprintf("%s %s", pkg.Manager, pkg.Name)
	if pkg.Version != "" {
		summary += "@" + pkg.Version
	}
	if pkg.Source != "" {
		summary += " source=" + pkg.Source
	}
	if len(pkg.NixNames) > 0 {
		summary += " nix=" + strings.Join(pkg.NixNames, ",")
	}
	return summary
}

func packageNotes(pkg model.Package) []string {
	var notes []string
	if len(pkg.NixNames) > 0 {
		notes = append(notes, "generates: package "+pkg.NixNames[0])
	} else {
		notes = append(notes, "review: no nix mapping")
	}
	notes = append(notes, detailNotes(pkg.Details)...)
	return notes
}

func gitSourceNotes(item model.GitSource) []string {
	var notes []string
	if item.Dirty {
		notes = append(notes, "review: dirty working tree")
	}
	if len(item.Build) > 0 {
		notes = append(notes, "detail: build-hints="+strings.Join(item.Build, ","))
	}
	return notes
}

func containerNotes(item model.Container) []string {
	var notes []string
	switch item.Runtime {
	case "docker":
		notes = append(notes, "generates: docker runtime enable when confirmed")
	case "podman":
		notes = append(notes, "generates: podman runtime enable when confirmed")
	case "compose":
		notes = append(notes, "review: compose file requires manual service/container translation")
	}
	if len(item.Ports) > 0 {
		notes = append(notes, "detail: ports="+strings.Join(item.Ports, ","))
	}
	if len(item.Mounts) > 0 {
		notes = append(notes, "detail: mounts="+strings.Join(item.Mounts, ","))
	}
	if len(item.Env) > 0 {
		notes = append(notes, fmt.Sprintf("detail: env-keys=%d", len(item.Env)))
	}
	return limitNotes(notes, 6)
}

func serviceNotes(item model.Service) []string {
	var notes []string
	if item.Manager == "systemd" {
		if strings.HasSuffix(item.Name, ".timer") {
			notes = append(notes, "generates: systemd timer options when confirmed and safe")
		} else {
			notes = append(notes, "generates: systemd service options when confirmed and safe")
		}
	}
	if item.User != "" {
		notes = append(notes, "detail: user="+item.User)
	}
	if item.WorkingDirectory != "" {
		notes = append(notes, "detail: working-directory="+item.WorkingDirectory)
	}
	if item.Schedule != "" {
		notes = append(notes, "detail: schedule="+item.Schedule)
	}
	if item.ExecStart != "" {
		notes = append(notes, "detail: exec="+redactSecretLikeText(item.ExecStart))
	}
	if len(item.EnvironmentFiles) > 0 {
		notes = append(notes, "review: environment files require manual migration")
	}
	return limitNotes(notes, 6)
}

func fileFindingNotes(item model.FileFinding, protected bool) []string {
	var notes []string
	if protected {
		notes = append(notes, "protected: cannot be confirmed")
	}
	if item.Size > 0 {
		notes = append(notes, fmt.Sprintf("detail: size=%d", item.Size))
	}
	if item.SHA256 != "" {
		notes = append(notes, "detail: sha256="+item.SHA256)
	}
	if item.Mode != "" {
		notes = append(notes, "detail: mode="+item.Mode)
	}
	if item.Owner != "" {
		notes = append(notes, "detail: owner="+item.Owner)
	}
	return limitNotes(notes, 6)
}

func itemNotes(item model.Item) []string {
	var notes []string
	notes = append(notes, detailNotes(item.Details)...)
	lower := strings.ToLower(item.Kind + " " + item.Reason)
	if strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "security") || strings.Contains(lower, "stateful") {
		notes = append(notes, "review: manual migration recommended")
	}
	return limitNotes(notes, 6)
}

func detailNotes(details map[string]string) []string {
	if len(details) == 0 {
		return nil
	}
	keys := make([]string, 0, len(details))
	for key := range details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var notes []string
	for _, key := range keys {
		value := redactSecretLikeText(details[key])
		if value == "" {
			continue
		}
		notes = append(notes, fmt.Sprintf("detail: %s=%s", key, value))
		if len(notes) == 4 {
			break
		}
	}
	return notes
}

func limitNotes(notes []string, limit int) []string {
	if len(notes) > limit {
		return notes[:limit]
	}
	return notes
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

func applyLanguagePackages(pkgs *[]model.Package, opts Options) {
	for i := range *pkgs {
		(*pkgs)[i].Decision = decidePackage((*pkgs)[i], opts)
	}
}

func decidePackage(pkg model.Package, opts Options) model.Decision {
	if pathExcluded(pkg.Source, opts.ExcludePathPrefixes) {
		return model.DecisionExcluded
	}
	if pkg.Decision != "" && pkg.Decision != model.DecisionCandidate {
		return pkg.Decision
	}
	if contains(opts.ConfirmManagers, pkg.Manager) {
		return model.DecisionConfirmed
	}
	if opts.AutoSafe && len(pkg.NixNames) > 0 {
		return model.DecisionConfirmed
	}
	return model.DecisionCandidate
}

func decideFinding(kind, path string, current model.Decision, secretRisk bool, opts Options) model.Decision {
	if secretRisk {
		return model.DecisionMigrationNote
	}
	if pathExcluded(path, opts.ExcludePathPrefixes) {
		return model.DecisionExcluded
	}
	if current != "" && current != model.DecisionCandidate {
		return current
	}
	switch {
	case contains(opts.ConfirmKinds, kind):
		return model.DecisionConfirmed
	case contains(opts.ExcludeKinds, kind):
		return model.DecisionExcluded
	case contains(opts.TODOKinds, kind):
		return model.DecisionTODO
	case contains(opts.MigrationNoteKinds, kind):
		return model.DecisionMigrationNote
	case opts.AutoSafe && (kind == "config" || kind == "os-config" || kind == "user-config" || kind == "service"):
		return model.DecisionCandidate
	default:
		return model.DecisionCandidate
	}
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func pathExcluded(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
