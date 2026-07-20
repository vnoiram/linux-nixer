package mapping

import "testing"

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
		{"python", "poetry", "poetry"},
		{"python", "pre-commit", "pre-commit"},
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
