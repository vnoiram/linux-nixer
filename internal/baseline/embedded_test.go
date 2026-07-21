package baseline

import (
	"strings"
	"testing"
)

func TestBundledManifestKnownLookups(t *testing.T) {
	cases := []struct {
		distro, release string
		wantPath        string // a file expected in this distro/release's real rootfs export
	}{
		{"ubuntu", "20.04", "/etc/hostname"},
		{"ubuntu", "22.04", "/etc/hostname"},
		{"ubuntu", "24.04", "/etc/hostname"},
		{"debian", "11", "/etc/hostname"},
		{"debian", "12", "/etc/hostname"},
		{"fedora", "40", "/etc/hosts"},
		{"fedora", "41", "/etc/hosts"},
		{" Ubuntu ", "24.04", "/etc/hostname"},
	}
	for _, tc := range cases {
		manifest, ok, err := BundledManifest(tc.distro, tc.release)
		if err != nil {
			t.Fatalf("BundledManifest(%q, %q) error: %v", tc.distro, tc.release, err)
		}
		if !ok || manifest == nil {
			t.Fatalf("BundledManifest(%q, %q)=(%v,%v), want a manifest", tc.distro, tc.release, manifest, ok)
		}
		wantDistro := strings.ToLower(strings.TrimSpace(tc.distro))
		wantRelease := strings.TrimSpace(tc.release)
		if manifest.Distro != wantDistro || manifest.Release != wantRelease {
			t.Fatalf("BundledManifest(%q, %q) distro/release=%q/%q, want %q/%q", tc.distro, tc.release, manifest.Distro, manifest.Release, wantDistro, wantRelease)
		}
		if manifest.SchemaVersion == "" {
			t.Fatalf("BundledManifest(%q, %q) has no schemaVersion", tc.distro, tc.release)
		}
		if len(manifest.Files) == 0 {
			t.Fatalf("BundledManifest(%q, %q) has no files", tc.distro, tc.release)
		}
		var sawExpectedFile bool
		for _, f := range manifest.Files {
			if f.Path == tc.wantPath {
				sawExpectedFile = true
				break
			}
		}
		if !sawExpectedFile {
			t.Fatalf("BundledManifest(%q, %q) missing expected %s entry", tc.distro, tc.release, tc.wantPath)
		}
	}
}

func TestBundledManifestUnknownStaysUnknown(t *testing.T) {
	cases := []struct{ distro, release string }{
		{"ubuntu", "16.04"},
		{"fedora", "39"},
		{"", ""},
	}
	for _, tc := range cases {
		manifest, ok, err := BundledManifest(tc.distro, tc.release)
		if err != nil {
			t.Fatalf("BundledManifest(%q, %q) unexpected error: %v", tc.distro, tc.release, err)
		}
		if ok || manifest != nil {
			t.Fatalf("BundledManifest(%q, %q)=(%v,%v), want (nil,false)", tc.distro, tc.release, manifest, ok)
		}
	}
}
