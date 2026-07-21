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
		for release, entry := range table {
			if strings.TrimSpace(release) != release {
				t.Fatalf("catalog[%q] release key %q is not trimmed", distro, release)
			}
			if strings.TrimSpace(entry.image) == "" {
				t.Fatalf("catalog[%q][%q] has an empty image reference", distro, release)
			}
		}
	}
}

func TestCatalogDigestsLookLikeSHA256(t *testing.T) {
	hexDigits := "0123456789abcdef"
	for distro, table := range catalog {
		for release, entry := range table {
			const prefix = "sha256:"
			if !strings.HasPrefix(entry.digest, prefix) {
				t.Fatalf("catalog[%q][%q] digest %q does not start with %q", distro, release, entry.digest, prefix)
			}
			hex := strings.TrimPrefix(entry.digest, prefix)
			if len(hex) != 64 {
				t.Fatalf("catalog[%q][%q] digest %q hex part has length %d, want 64", distro, release, entry.digest, len(hex))
			}
			for _, c := range hex {
				if !strings.ContainsRune(hexDigits, c) {
					t.Fatalf("catalog[%q][%q] digest %q contains non-hex character %q", distro, release, entry.digest, c)
				}
			}
		}
	}
}

func TestCatalogDigestKnownLookups(t *testing.T) {
	if _, ok := CatalogDigest("ubuntu", "24.04"); !ok {
		t.Fatal("CatalogDigest(ubuntu, 24.04) should resolve")
	}
	if _, ok := CatalogDigest(" Debian ", "12"); !ok {
		t.Fatal("CatalogDigest(Debian, 12) should resolve with normalization")
	}
}

func TestCatalogDigestUnknownStaysUnknown(t *testing.T) {
	if _, ok := CatalogDigest("fedora", "40"); ok {
		t.Fatal("CatalogDigest(fedora, 40) should not resolve")
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
