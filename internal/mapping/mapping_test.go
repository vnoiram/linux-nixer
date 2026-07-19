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
		{"npm", "typescript", "nodePackages.typescript"},
		{"pipx", "ruff", "ruff"},
		{"python", "poetry", "poetry"},
		{"cargo", "starship", "starship"},
		{"go-install", "gopls", "gopls"},
		{"gem", "bundler", "bundler"},
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
