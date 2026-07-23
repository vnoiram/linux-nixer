package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
