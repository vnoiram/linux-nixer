package review

import (
	"errors"
	"fmt"

	"github.com/vnoiram/linux-nixer/internal/model"
)

const DecisionsSchemaVersion = "linux-nixer.decisions.v1"

// DecisionEntry is one previously-made decision, identified by a stable
// domain+key pair rather than by position in a scan report, so it can be
// carried across a re-scan of the same host, a rescan after drift, or a
// teammate's scan of a similar machine.
type DecisionEntry struct {
	Domain   string         `json:"domain"`
	Key      string         `json:"key"`
	Decision model.Decision `json:"decision"`
}

// DecisionSet is a portable, host-independent export of review decisions.
// Its keys mirror the identity fields applyDecisions already uses per
// domain (manager+name for packages/services, path for git sources and
// file findings, kind+path for items), not the raw scan data itself.
type DecisionSet struct {
	SchemaVersion string          `json:"schemaVersion"`
	Entries       []DecisionEntry `json:"entries"`
}

func (s DecisionSet) Validate() error {
	if s.SchemaVersion == "" {
		return errors.New("decisions schemaVersion is required")
	}
	if s.SchemaVersion != DecisionsSchemaVersion {
		return fmt.Errorf("unsupported decisions schemaVersion %q, want %q", s.SchemaVersion, DecisionsSchemaVersion)
	}
	return nil
}

// ExportDecisions collects every finding whose Decision is something other
// than the default "not yet decided" state (empty or candidate) into a
// portable DecisionSet. Desktop.Autostart is intentionally excluded: it's
// never touched by applyDecisions/Interactive today, so it never carries a
// real decision to export.
func ExportDecisions(report model.ScanReport) DecisionSet {
	var entries []DecisionEntry
	add := func(domain, key string, decision model.Decision) {
		if key == "" || decision == "" || decision == model.DecisionCandidate {
			return
		}
		entries = append(entries, DecisionEntry{Domain: domain, Key: key, Decision: decision})
	}

	for _, pkg := range allPackages(report) {
		add("package", packageDecisionKey(pkg), pkg.Decision)
	}
	for _, g := range report.GitSources {
		add("git-source", g.Path, g.Decision)
	}
	for _, c := range report.Containers {
		add("container", containerDecisionKey(c), c.Decision)
	}
	for _, s := range report.Services {
		add("service", serviceDecisionKey(s), s.Decision)
	}
	for _, f := range report.FilesystemDiff {
		add("filesystem-finding", f.Path, f.Decision)
	}
	for _, f := range report.StatefulData {
		add("stateful-data", f.Path, f.Decision)
	}
	for _, it := range report.Items {
		add("item", itemDecisionKey(it), it.Decision)
	}

	return DecisionSet{SchemaVersion: DecisionsSchemaVersion, Entries: entries}
}

// ApplyDecisions seeds report with decisions from set, matched by the same
// domain+key identity ExportDecisions used. Findings with no matching entry
// are left untouched (default candidate); entries with no matching finding
// in report are silently dropped. Called before review.Apply/Interactive so
// the existing "already decided" precedence in decidePackage/decideFinding
// makes an imported decision win over a policy's category-level rules.
func ApplyDecisions(report model.ScanReport, set DecisionSet) model.ScanReport {
	lookup := map[string]map[string]model.Decision{}
	for _, e := range set.Entries {
		if lookup[e.Domain] == nil {
			lookup[e.Domain] = map[string]model.Decision{}
		}
		lookup[e.Domain][e.Key] = e.Decision
	}

	applyPackages := func(pkgs []model.Package) {
		for i := range pkgs {
			if d, ok := lookup["package"][packageDecisionKey(pkgs[i])]; ok {
				pkgs[i].Decision = d
			}
		}
	}
	applyPackages(report.Packages)
	applyPackages(report.Languages.NPM)
	applyPackages(report.Languages.Conda)
	applyPackages(report.Languages.Cargo)
	applyPackages(report.Languages.Gem)
	applyPackages(report.Languages.Go)
	for i := range report.Languages.Python {
		applyPackages(report.Languages.Python[i].Packages)
	}

	for i := range report.GitSources {
		if d, ok := lookup["git-source"][report.GitSources[i].Path]; ok {
			report.GitSources[i].Decision = d
		}
	}
	for i := range report.Containers {
		if d, ok := lookup["container"][containerDecisionKey(report.Containers[i])]; ok {
			report.Containers[i].Decision = d
		}
	}
	for i := range report.Services {
		if d, ok := lookup["service"][serviceDecisionKey(report.Services[i])]; ok {
			report.Services[i].Decision = d
		}
	}
	for i := range report.FilesystemDiff {
		if d, ok := lookup["filesystem-finding"][report.FilesystemDiff[i].Path]; ok {
			report.FilesystemDiff[i].Decision = d
		}
	}
	for i := range report.StatefulData {
		if d, ok := lookup["stateful-data"][report.StatefulData[i].Path]; ok {
			report.StatefulData[i].Decision = d
		}
	}
	for i := range report.Items {
		if d, ok := lookup["item"][itemDecisionKey(report.Items[i])]; ok {
			report.Items[i].Decision = d
		}
	}

	return report
}

func allPackages(report model.ScanReport) []model.Package {
	var out []model.Package
	out = append(out, report.Packages...)
	out = append(out, report.Languages.NPM...)
	out = append(out, report.Languages.Conda...)
	out = append(out, report.Languages.Cargo...)
	out = append(out, report.Languages.Gem...)
	out = append(out, report.Languages.Go...)
	for _, env := range report.Languages.Python {
		out = append(out, env.Packages...)
	}
	return out
}

func packageDecisionKey(pkg model.Package) string {
	return pkg.Manager + ":" + pkg.Name
}

func containerDecisionKey(c model.Container) string {
	name := c.Name
	if name == "" {
		name = c.Compose
	}
	return c.Runtime + ":" + name
}

func serviceDecisionKey(s model.Service) string {
	return s.Manager + ":" + s.Name
}

func itemDecisionKey(it model.Item) string {
	return it.Kind + ":" + it.Path
}
