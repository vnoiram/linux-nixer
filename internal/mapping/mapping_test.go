package mapping

import (
	"strings"
	"testing"
)

func TestCandidatesKnownMappings(t *testing.T) {
	cases := []struct {
		manager string
		name    string
		want    string
	}{
		{"apt", "fd-find", "fd"},
		{"apt", "docker.io", "docker"},
		{"apt", "shellcheck", "shellcheck"},
		{"apt", "postgresql-client", "postgresql"},
		{"npm", "typescript", "nodePackages.typescript"},
		{"npm", "vite", "nodePackages.vite"},
		{"pipx", "ruff", "ruff"},
		{"pipx", "uv", "uv"},
		{"cargo", "starship", "starship"},
		{"cargo", "git-delta", "delta"},
		{"go-install", "gopls", "gopls"},
		{"go-install", "buf", "buf"},
		{"gem", "bundler", "bundler"},
		{"gem", "rubocop", "rubocop"},
	}
	for _, tc := range cases {
		got := Candidates(tc.manager, tc.name)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("Candidates(%q, %q)=%v, want [%s]", tc.manager, tc.name, got, tc.want)
		}
	}
}

func TestCandidatesNormalizeNamesAndAliases(t *testing.T) {
	cases := []struct {
		manager string
		name    string
		want    string
	}{
		{"APT", " FD ", "fd"},
		{"npm", "TypeScript", "nodePackages.typescript"},
		{"cargo", "fd-find", "fd"},
		{"cargo", "bottom", "bottom"},
		{"go-install", "delve", "delve"},
	}
	for _, tc := range cases {
		got := Candidates(tc.manager, tc.name)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("Candidates(%q, %q)=%v, want [%s]", tc.manager, tc.name, got, tc.want)
		}
	}
}

func TestCandidatesUnknownAndConservativeManagers(t *testing.T) {
	for _, tc := range []struct {
		manager string
		name    string
	}{
		{"apt", "unknown"},
		{"snap", "firefox"},
		{"flatpak", "org.mozilla.firefox"},
		{"appimage", "Tool"},
		{"homebrew", "hello"},
	} {
		if got := Candidates(tc.manager, tc.name); got != nil {
			t.Fatalf("Candidates(%q, %q)=%v, want nil", tc.manager, tc.name, got)
		}
	}
}

func TestMappingKeysAreNormalized(t *testing.T) {
	for manager, table := range mappings {
		for key := range table {
			if normalized := strings.ToLower(strings.TrimSpace(key)); normalized != key {
				t.Fatalf("mappings[%q] key %q is not normalized (want %q); it would be unreachable via Candidates", manager, key, normalized)
			}
		}
	}
}

func TestMappingValuesAreNonEmpty(t *testing.T) {
	for manager, table := range mappings {
		for key, value := range table {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("mappings[%q][%q] has an empty value", manager, key)
			}
		}
	}
}

func TestMappingAliasesResolveToRealEntries(t *testing.T) {
	for manager, aliases := range mappingAliases {
		table := mappings[manager]
		for name, target := range aliases {
			if _, ok := table[target]; !ok {
				t.Fatalf("mappingAliases[%q][%q] targets %q, which is not a key in mappings[%q]", manager, name, target, manager)
			}
		}
	}
}

func TestMappingAliasManagersExist(t *testing.T) {
	for manager := range mappingAliases {
		if _, ok := mappings[manager]; !ok {
			t.Fatalf("mappingAliases has manager %q with no corresponding mappings table", manager)
		}
	}
}
