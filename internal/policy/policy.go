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
		return Policy{}, fmt.Errorf("unknown policy preset %q; supported presets: %s", preset, strings.Join(PresetNames, ", "))
	}
	p.AutoSafe = &autoSafe
	return p, nil
}

func Load(path string) (Policy, error) {
	if path == "" {
		return Policy{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, err
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
