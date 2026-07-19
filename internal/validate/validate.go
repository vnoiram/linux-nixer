package validate

import (
	"fmt"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type Result struct {
	OK       bool    `json:"ok"`
	Checked  int     `json:"checked"`
	Errors   []Issue `json:"errors,omitempty"`
	Warnings []Issue `json:"warnings,omitempty"`
}

type Issue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func ScanReport(report model.ScanReport) Result {
	v := validator{}
	if report.SchemaVersion == "" {
		v.error("schemaVersion", "missing schema version")
	} else if report.SchemaVersion != model.SchemaVersion {
		v.error("schemaVersion", fmt.Sprintf("unsupported schema version %q, want %q", report.SchemaVersion, model.SchemaVersion))
	}

	for i, user := range report.Users {
		path := fmt.Sprintf("users[%d]", i)
		v.checked()
		if user.Name == "" {
			v.error(path+".name", "user name is required")
		}
	}
	for i, pkg := range report.Packages {
		v.packageFinding(fmt.Sprintf("packages[%d]", i), pkg)
	}
	v.packageFindings("languages.npm", report.Languages.NPM)
	for i, env := range report.Languages.Python {
		path := fmt.Sprintf("languages.python[%d]", i)
		v.checked()
		if env.Path == "" {
			v.error(path+".path", "python environment path is required")
		}
		if env.Kind == "" {
			v.error(path+".kind", "python environment kind is required")
		}
		v.packageFindings(path+".packages", env.Packages)
	}
	v.packageFindings("languages.conda", report.Languages.Conda)
	v.packageFindings("languages.cargo", report.Languages.Cargo)
	v.packageFindings("languages.gem", report.Languages.Gem)
	v.packageFindings("languages.go", report.Languages.Go)
	for i, vm := range report.Languages.VMs {
		path := fmt.Sprintf("languages.versionManagers[%d]", i)
		v.checked()
		if vm.Name == "" {
			v.error(path+".name", "version manager name is required")
		}
	}
	for i, source := range report.GitSources {
		path := fmt.Sprintf("gitSources[%d]", i)
		v.checked()
		if source.Path == "" {
			v.error(path+".path", "git source path is required")
		}
		v.decision(path+".decision", source.Decision)
	}
	for i, container := range report.Containers {
		path := fmt.Sprintf("containers[%d]", i)
		v.checked()
		if container.Runtime == "" {
			v.error(path+".runtime", "container runtime is required")
		}
		if container.Name == "" && container.Compose == "" {
			v.error(path, "container name or compose path is required")
		}
		v.decision(path+".decision", container.Decision)
	}
	for i, file := range report.Desktop.Autostart {
		v.fileFinding(fmt.Sprintf("desktop.autostart[%d]", i), file, false)
	}
	for i, service := range report.Services {
		path := fmt.Sprintf("services[%d]", i)
		v.checked()
		if service.Manager == "" {
			v.error(path+".manager", "service manager is required")
		}
		if service.Name == "" {
			v.error(path+".name", "service name is required")
		}
		v.decision(path+".decision", service.Decision)
	}
	for i, file := range report.FilesystemDiff {
		v.fileFinding(fmt.Sprintf("filesystemDiff[%d]", i), file, false)
	}
	for i, file := range report.StatefulData {
		v.fileFinding(fmt.Sprintf("statefulData[%d]", i), file, true)
	}
	for i, item := range report.Items {
		path := fmt.Sprintf("items[%d]", i)
		v.checked()
		if item.Kind == "" {
			v.error(path+".kind", "item kind is required")
		}
		if item.Path == "" && item.Name == "" {
			v.error(path, "item path or name is required")
		}
		v.decision(path+".decision", item.Decision)
	}
	result := Result{OK: len(v.errors) == 0, Checked: v.count, Errors: v.errors, Warnings: v.warnings}
	return result
}

type validator struct {
	count    int
	errors   []Issue
	warnings []Issue
}

func (v *validator) checked() {
	v.count++
}

func (v *validator) error(path, message string) {
	v.errors = append(v.errors, Issue{Path: path, Message: message})
}

func (v *validator) warning(path, message string) {
	v.warnings = append(v.warnings, Issue{Path: path, Message: message})
}

func (v *validator) packageFindings(prefix string, pkgs []model.Package) {
	for i, pkg := range pkgs {
		v.packageFinding(fmt.Sprintf("%s[%d]", prefix, i), pkg)
	}
}

func (v *validator) packageFinding(path string, pkg model.Package) {
	v.checked()
	if pkg.Manager == "" {
		v.error(path+".manager", "package manager is required")
	}
	if pkg.Name == "" {
		v.error(path+".name", "package name is required")
	}
	v.decision(path+".decision", pkg.Decision)
}

func (v *validator) fileFinding(path string, file model.FileFinding, stateful bool) {
	v.checked()
	if file.Path == "" {
		v.error(path+".path", "file path is required")
	}
	if file.SecretRisk && file.Decision == model.DecisionConfirmed {
		v.error(path+".decision", "secret-risk finding cannot be confirmed")
	}
	if stateful && file.Decision == model.DecisionConfirmed {
		v.error(path+".decision", "stateful data cannot be confirmed")
	}
	if file.Decision == "" {
		v.warning(path+".decision", "file finding has no review decision")
	}
	v.decision(path+".decision", file.Decision)
}

func (v *validator) decision(path string, decision model.Decision) {
	switch decision {
	case "", model.DecisionConfirmed, model.DecisionCandidate, model.DecisionTODO, model.DecisionMigrationNote, model.DecisionExcluded:
		return
	default:
		v.error(path, fmt.Sprintf("unknown decision %q", decision))
	}
}
