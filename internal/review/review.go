package review

import (
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
	report.Warnings = append(report.Warnings, model.Warning{
		Source:  "review",
		Message: "review decisions applied non-interactively; use generated reports before applying Nix output",
	})
	return report
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
