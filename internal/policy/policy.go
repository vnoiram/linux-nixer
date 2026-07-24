package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/scanner"
)

const SchemaVersion = "linux-nixer.policy.v1"

// PresetNames lists the valid Template preset names, in the order they're
// documented in CLI help text. Keep this in sync with Template's switch.
// "default" is Template's generic/no-op case (AutoSafe on, everything else
// empty) — listed explicitly so it's a discoverable, intentional choice
// (e.g. for `scan`/`capture --preset default`) rather than only reachable
// by omitting a preset name.
var PresetNames = []string{"default", "workstation", "server", "developer-machine", "minimal-audit"}

type Policy struct {
	SchemaVersion       string   `json:"schemaVersion"`
	AutoSafe            *bool    `json:"autoSafe,omitempty"`
	ConfirmKinds        []string `json:"confirmKinds,omitempty"`
	ExcludeKinds        []string `json:"excludeKinds,omitempty"`
	TODOKinds           []string `json:"todoKinds,omitempty"`
	MigrationNoteKinds  []string `json:"migrationNoteKinds,omitempty"`
	ConfirmManagers     []string `json:"confirmManagers,omitempty"`
	ExcludePathPrefixes []string `json:"excludePathPrefixes,omitempty"`
	IncludePaths        []string `json:"includePaths,omitempty"`
	ExcludePaths        []string `json:"excludePaths,omitempty"`
	Deep                *bool    `json:"deep,omitempty"`
	Sudo                *bool    `json:"sudo,omitempty"`
	Baseline            string   `json:"baseline,omitempty"`
	Plugins             []string `json:"plugins,omitempty"`
}

type PresetDiff struct {
	From            string      `json:"from"`
	To              string      `json:"to"`
	AutoSafeChanged bool        `json:"autoSafeChanged"`
	FromAutoSafe    bool        `json:"fromAutoSafe"`
	ToAutoSafe      bool        `json:"toAutoSafe"`
	Fields          []FieldDiff `json:"fields"`
}

type FieldDiff struct {
	Name    string   `json:"name"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

type LintIssue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type LintResult struct {
	OK       bool        `json:"ok"`
	Checked  int         `json:"checked"`
	Errors   []LintIssue `json:"errors,omitempty"`
	Warnings []LintIssue `json:"warnings,omitempty"`
}

// Template returns a policy template, optionally tuned by a named preset
// for a common migration style. preset == "" (or "default") returns the
// generic template: AutoSafe on, everything else empty. A known preset name
// layers ConfirmKinds/ExcludeKinds/AutoSafe on top of that. ConfirmManagers
// is deliberately left empty by every preset: it unconditionally confirms
// every package from a manager regardless of whether a Nix mapping exists,
// a stronger statement than a preset should make on the user's behalf.
func Template(preset string) (Policy, error) {
	p := Policy{
		SchemaVersion:       SchemaVersion,
		ConfirmKinds:        []string{},
		ExcludeKinds:        []string{},
		TODOKinds:           []string{},
		MigrationNoteKinds:  []string{},
		ConfirmManagers:     []string{},
		ExcludePathPrefixes: []string{},
		IncludePaths:        []string{},
		ExcludePaths:        []string{},
		Plugins:             []string{},
	}
	autoSafe := true
	switch preset {
	case "", "default":
	case "workstation":
		p.ConfirmKinds = []string{"desktop-config", "shell-config", "user-config", "direnv"}
	case "server":
		p.ConfirmKinds = []string{"service", "container", "os-config"}
		p.ExcludeKinds = []string{"desktop-config", "shell-plugin"}
	case "developer-machine":
		p.ConfirmKinds = []string{"dev-project", "git-source", "language-project", "shell-config", "direnv"}
	case "minimal-audit":
		autoSafe = false
	default:
		return Policy{}, fmt.Errorf("unknown policy preset %q; supported presets: %s; run `linux-nixer policy init --preset workstation --out linux-nixer-policy.json` to create a preset policy", preset, strings.Join(PresetNames, ", "))
	}
	p.AutoSafe = &autoSafe
	return p, nil
}

func DiffPresets(from, to string) (PresetDiff, error) {
	if from == "" || to == "" {
		return PresetDiff{}, errors.New("policy diff requires --from and --to")
	}
	fromPolicy, err := Template(from)
	if err != nil {
		return PresetDiff{}, err
	}
	toPolicy, err := Template(to)
	if err != nil {
		return PresetDiff{}, err
	}
	diff := PresetDiff{From: from, To: to}
	if fromPolicy.AutoSafe != nil {
		diff.FromAutoSafe = *fromPolicy.AutoSafe
	}
	if toPolicy.AutoSafe != nil {
		diff.ToAutoSafe = *toPolicy.AutoSafe
	}
	diff.AutoSafeChanged = diff.FromAutoSafe != diff.ToAutoSafe
	fields := []struct {
		name string
		a    []string
		b    []string
	}{
		{name: "confirmKinds", a: fromPolicy.ConfirmKinds, b: toPolicy.ConfirmKinds},
		{name: "excludeKinds", a: fromPolicy.ExcludeKinds, b: toPolicy.ExcludeKinds},
		{name: "todoKinds", a: fromPolicy.TODOKinds, b: toPolicy.TODOKinds},
		{name: "migrationNoteKinds", a: fromPolicy.MigrationNoteKinds, b: toPolicy.MigrationNoteKinds},
		{name: "confirmManagers", a: fromPolicy.ConfirmManagers, b: toPolicy.ConfirmManagers},
		{name: "excludePathPrefixes", a: fromPolicy.ExcludePathPrefixes, b: toPolicy.ExcludePathPrefixes},
		{name: "includePaths", a: fromPolicy.IncludePaths, b: toPolicy.IncludePaths},
		{name: "excludePaths", a: fromPolicy.ExcludePaths, b: toPolicy.ExcludePaths},
		{name: "plugins", a: fromPolicy.Plugins, b: toPolicy.Plugins},
	}
	for _, field := range fields {
		fd := FieldDiff{
			Name:    field.name,
			Added:   listDifference(field.b, field.a),
			Removed: listDifference(field.a, field.b),
		}
		if len(fd.Added) > 0 || len(fd.Removed) > 0 {
			diff.Fields = append(diff.Fields, fd)
		}
	}
	return diff, nil
}

func Load(path string) (Policy, error) {
	if path == "" {
		return Policy{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("could not read policy %q: %w; create one with `linux-nixer policy init --out linux-nixer-policy.json`", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	return p, p.Validate()
}

func WriteTemplate(path, preset string) error {
	if path == "" {
		return errors.New("policy init requires --out")
	}
	tmpl, err := Template(preset)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(tmpl)
}

func (p Policy) Validate() error {
	if p.SchemaVersion == "" {
		return errors.New("policy schemaVersion is required")
	}
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported policy schemaVersion %q, want %q", p.SchemaVersion, SchemaVersion)
	}
	fields := map[string][]string{
		"confirmKinds":        p.ConfirmKinds,
		"excludeKinds":        p.ExcludeKinds,
		"todoKinds":           p.TODOKinds,
		"migrationNoteKinds":  p.MigrationNoteKinds,
		"confirmManagers":     p.ConfirmManagers,
		"excludePathPrefixes": p.ExcludePathPrefixes,
		"includePaths":        p.IncludePaths,
		"excludePaths":        p.ExcludePaths,
		"plugins":             p.Plugins,
	}
	for field, values := range fields {
		for i, value := range values {
			if value == "" {
				return fmt.Errorf("%s[%d] must not be empty", field, i)
			}
		}
	}
	return nil
}

func Lint(p Policy) LintResult {
	result := LintResult{OK: true}
	if err := p.Validate(); err != nil {
		result.OK = false
		result.Errors = append(result.Errors, LintIssue{Path: "policy", Message: err.Error()})
		return result
	}
	lists := map[string][]string{
		"confirmKinds":       p.ConfirmKinds,
		"excludeKinds":       p.ExcludeKinds,
		"todoKinds":          p.TODOKinds,
		"migrationNoteKinds": p.MigrationNoteKinds,
		"confirmManagers":    p.ConfirmManagers,
		"includePaths":       p.IncludePaths,
		"excludePaths":       p.ExcludePaths,
		"plugins":            p.Plugins,
	}
	for field, values := range lists {
		result.Checked += len(values)
		for _, duplicate := range duplicates(values) {
			result.Warnings = append(result.Warnings, LintIssue{Path: field, Message: fmt.Sprintf("duplicate value %q", duplicate)})
		}
	}
	kindFields := map[string][]string{
		"confirmKinds":       p.ConfirmKinds,
		"excludeKinds":       p.ExcludeKinds,
		"todoKinds":          p.TODOKinds,
		"migrationNoteKinds": p.MigrationNoteKinds,
	}
	for field, values := range kindFields {
		for _, value := range values {
			if !knownPolicyKind(value) {
				result.Warnings = append(result.Warnings, LintIssue{Path: field, Message: fmt.Sprintf("unknown kind %q; custom plugin kinds are allowed but should be intentional", value)})
			}
		}
	}
	fields := []struct {
		name   string
		values []string
	}{
		{name: "confirmKinds", values: p.ConfirmKinds},
		{name: "excludeKinds", values: p.ExcludeKinds},
		{name: "todoKinds", values: p.TODOKinds},
		{name: "migrationNoteKinds", values: p.MigrationNoteKinds},
	}
	for i := 0; i < len(fields); i++ {
		for j := i + 1; j < len(fields); j++ {
			for _, value := range intersection(fields[i].values, fields[j].values) {
				result.Errors = append(result.Errors, LintIssue{
					Path:    fields[i].name + "/" + fields[j].name,
					Message: fmt.Sprintf("kind %q appears in contradictory decision lists", value),
				})
			}
		}
	}
	if len(result.Errors) > 0 {
		result.OK = false
	}
	return result
}

func (p Policy) ScanOptions(base scanner.Options) scanner.Options {
	if p.Sudo != nil {
		base.UseSudo = *p.Sudo
	}
	if p.Deep != nil {
		base.Deep = *p.Deep
	}
	if p.Baseline != "" {
		base.BaselineID = p.Baseline
	}
	base.Includes = Merge(base.Includes, p.IncludePaths)
	base.Excludes = Merge(base.Excludes, p.ExcludePaths)
	return base
}

func (p Policy) ReviewOptions(base review.Options) review.Options {
	if p.AutoSafe != nil {
		base.AutoSafe = *p.AutoSafe
	}
	base.ConfirmKinds = Merge(base.ConfirmKinds, p.ConfirmKinds)
	base.ExcludeKinds = Merge(base.ExcludeKinds, p.ExcludeKinds)
	base.TODOKinds = Merge(base.TODOKinds, p.TODOKinds)
	base.MigrationNoteKinds = Merge(base.MigrationNoteKinds, p.MigrationNoteKinds)
	base.ConfirmManagers = Merge(base.ConfirmManagers, p.ConfirmManagers)
	base.ExcludePathPrefixes = Merge(base.ExcludePathPrefixes, p.ExcludePathPrefixes)
	return base
}

func Merge(primary []string, secondary []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, values := range [][]string{secondary, primary} {
		for _, value := range values {
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func listDifference(values, subtract []string) []string {
	skip := map[string]bool{}
	for _, value := range subtract {
		skip[value] = true
	}
	var out []string
	for _, value := range values {
		if value == "" || skip[value] {
			continue
		}
		out = append(out, value)
	}
	return out
}

func duplicates(values []string) []string {
	seen := map[string]bool{}
	reported := map[string]bool{}
	var out []string
	for _, value := range values {
		if seen[value] && !reported[value] {
			out = append(out, value)
			reported[value] = true
		}
		seen[value] = true
	}
	sort.Strings(out)
	return out
}

func intersection(a, b []string) []string {
	inB := map[string]bool{}
	for _, value := range b {
		inB[value] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range a {
		if value != "" && inB[value] && !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	sort.Strings(out)
	return out
}

func knownPolicyKind(kind string) bool {
	known := map[string]bool{
		"apt-config":        true,
		"apt-keyring":       true,
		"apt-preference":    true,
		"apt-source":        true,
		"backup-config":     true,
		"browser-extension": true,
		"browser-profile":   true,
		"cicd-config":       true,
		"config":            true,
		"container":         true,
		"credential-store":  true,
		"desktop-autostart": true,
		"desktop-config":    true,
		"dev-project":       true,
		"devops-config":     true,
		"direnv":            true,
		"editor-profile":    true,
		"git-source":        true,
		"hardware-config":   true,
		"language-project":  true,
		"os-config":         true,
		"service":           true,
		"shell-config":      true,
		"shell-plugin":      true,
		"stateful-data":     true,
		"user-bin":          true,
		"user-config":       true,
	}
	return known[kind]
}
