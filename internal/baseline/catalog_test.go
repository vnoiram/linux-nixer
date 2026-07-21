package baseline

import (
	"strings"
	"testing"
)

func TestCatalogImageKnownLookups(t *testing.T) {
	cases := []struct {
		distro  string
		release string
		want    string
	}{
		{"ubuntu", "24.04", "ubuntu:24.04"},
		{"ubuntu", "22.04", "ubuntu:22.04"},
		{"debian", "12", "debian:12"},
		{" Ubuntu ", "24.04", "ubuntu:24.04"},
	}
	for _, tc := range cases {
		got, ok := CatalogImage(tc.distro, tc.release)
		if !ok || got != tc.want {
			t.Fatalf("CatalogImage(%q, %q)=(%q,%v), want (%q,true)", tc.distro, tc.release, got, ok, tc.want)
		}
	}
}

func TestCatalogImageUnknownStaysUnknown(t *testing.T) {
	cases := []struct{ distro, release string }{
		{"ubuntu", "16.04"},
		{"fedora", "40"},
		{"debian", "bookworm"},
		{"", ""},
	}
	for _, tc := range cases {
		if _, ok := CatalogImage(tc.distro, tc.release); ok {
			t.Fatalf("CatalogImage(%q, %q) should not resolve", tc.distro, tc.release)
		}
	}
}

func TestCatalogKeysAreNormalized(t *testing.T) {
	for distro, table := range catalog {
		if normalized := strings.ToLower(strings.TrimSpace(distro)); normalized != distro {
			t.Fatalf("catalog distro key %q is not normalized (want %q); it would be unreachable via CatalogImage", distro, normalized)
		}
		for release, image := range table {
			if strings.TrimSpace(release) != release {
				t.Fatalf("catalog[%q] release key %q is not trimmed", distro, release)
			}
			if strings.TrimSpace(image) == "" {
				t.Fatalf("catalog[%q][%q] has an empty image reference", distro, release)
			}
		}
	}
}

func TestCatalogEntriesSorted(t *testing.T) {
	entries := CatalogEntries()
	if len(entries) == 0 {
		t.Fatal("expected at least one catalog entry")
	}
	for i := 1; i < len(entries); i++ {
		prev, cur := entries[i-1], entries[i]
		if prev.Distro > cur.Distro {
			t.Fatalf("entries not sorted by distro: %+v before %+v", prev, cur)
		}
		if prev.Distro == cur.Distro && prev.Release > cur.Release {
			t.Fatalf("entries not sorted by release within distro: %+v before %+v", prev, cur)
		}
	}
}
