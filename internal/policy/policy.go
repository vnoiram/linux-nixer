package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/scanner"
)

const SchemaVersion = "linux-nixer.policy.v1"

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
}

func Template() Policy {
	autoSafe := true
	return Policy{
		SchemaVersion:       SchemaVersion,
		AutoSafe:            &autoSafe,
		ConfirmKinds:        []string{},
		ExcludeKinds:        []string{},
		TODOKinds:           []string{},
		MigrationNoteKinds:  []string{},
		ConfirmManagers:     []string{},
		ExcludePathPrefixes: []string{},
		IncludePaths:        []string{},
		ExcludePaths:        []string{},
	}
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

func WriteTemplate(path string) error {
	if path == "" {
		return errors.New("policy init requires --out")
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
	return enc.Encode(Template())
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
