package review

import (
	"bufio"
	"fmt"
	"io"
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
	session := interactiveSession{in: bufio.NewScanner(in), out: out, quit: false}
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
	in   *bufio.Scanner
	out  io.Writer
	quit bool
}

func (s *interactiveSession) reviewPackages(section string, pkgs []model.Package, set func(int, model.Decision)) {
	for i, pkg := range pkgs {
		if s.quit {
			return
		}
		s.reviewDecision(section, i+1, packageSummary(pkg), pkg.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewGitSources(items []model.GitSource, set func(int, model.Decision)) {
	for i, item := range items {
		if s.quit {
			return
		}
		s.reviewDecision("git sources", i+1, fmt.Sprintf("%s remote=%s commit=%s", item.Path, item.Remote, item.Commit), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewContainers(items []model.Container, set func(int, model.Decision)) {
	for i, item := range items {
		if s.quit {
			return
		}
		name := item.Name
		if name == "" {
			name = item.Compose
		}
		s.reviewDecision("containers", i+1, fmt.Sprintf("%s %s image=%s", item.Runtime, name, item.Image), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewServices(items []model.Service, set func(int, model.Decision)) {
	for i, item := range items {
		if s.quit {
			return
		}
		s.reviewDecision("services", i+1, fmt.Sprintf("%s %s %s", item.Manager, item.Name, item.Path), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewFiles(section string, items []model.FileFinding, forceMigrationNote bool, set func(int, model.Decision)) {
	for i, item := range items {
		if s.quit {
			return
		}
		s.reviewDecision(section, i+1, fmt.Sprintf("%s %s %s", item.Category, item.Path, item.Reason), item.Decision, item.SecretRisk || forceMigrationNote, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewItems(items []model.Item, set func(int, model.Decision)) {
	for i, item := range items {
		if s.quit {
			return
		}
		s.reviewDecision("config/items", i+1, fmt.Sprintf("%s %s %s", item.Kind, item.Path, item.Reason), item.Decision, false, func(decision model.Decision) { set(i, decision) })
	}
}

func (s *interactiveSession) reviewDecision(section string, index int, summary string, current model.Decision, protected bool, set func(model.Decision)) {
	if current == "" {
		current = model.DecisionCandidate
	}
	fmt.Fprintf(s.out, "\n[%s #%d]\n%s\ncurrent: %s\n", section, index, summary, current)
	fmt.Fprint(s.out, "choose c=confirmed k=candidate t=todo m=migration-note x=excluded s=skip q=quit: ")
	if !s.in.Scan() {
		s.quit = true
		return
	}
	choice := strings.TrimSpace(strings.ToLower(s.in.Text()))
	decision, ok := choiceDecision(choice)
	if choice == "q" {
		s.quit = true
		return
	}
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

func applyLanguagePackages(pkgs *[]model.Package, opts Options) {
	for i := range *pkgs {
		(*pkgs)[i].Decision = decidePackage((*pkgs)[i], opts)
	}
}

func decidePackage(pkg model.Package, opts Options) model.Decision {
	if pathExcluded(pkg.Source, opts.ExcludePathPrefixes) {
		return model.DecisionExcluded
	}
	if contains(opts.ConfirmManagers, pkg.Manager) {
		return model.DecisionConfirmed
	}
	if pkg.Decision != "" {
		return pkg.Decision
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
	switch {
	case contains(opts.ConfirmKinds, kind):
		return model.DecisionConfirmed
	case contains(opts.ExcludeKinds, kind):
		return model.DecisionExcluded
	case contains(opts.TODOKinds, kind):
		return model.DecisionTODO
	case contains(opts.MigrationNoteKinds, kind):
		return model.DecisionMigrationNote
	case current != "":
		return current
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
