package baseline

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCheckCatalogReportsMatchAndDrift(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "inspect" {
			// Report the ubuntu:24.04 entry as unchanged, and drift every
			// other entry by returning a digest that never matches the
			// catalog's pinned value.
			if strings.Contains(args[len(args)-1], "ubuntu:24.04") {
				digest, _ := CatalogDigest("ubuntu", "24.04")
				return []byte("docker.io/library/ubuntu@" + digest), nil
			}
			return []byte("docker.io/library/whatever@sha256:0000000000000000000000000000000000000000000000000000000000000000"), nil
		}
		return nil, nil
	}

	results, err := CheckCatalog(context.Background(), CatalogCheckOptions{Backend: "docker", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(CatalogEntries()) {
		t.Fatalf("got %d results, want %d (one per catalog entry)", len(results), len(CatalogEntries()))
	}

	var sawMatch, sawDrift bool
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("unexpected error for %s:%s: %s", r.Distro, r.Release, r.Error)
		}
		if r.Distro == "ubuntu" && r.Release == "24.04" {
			if r.Drifted {
				t.Fatalf("ubuntu:24.04 should not be reported as drifted: %+v", r)
			}
			if r.CurrentDigest != r.PinnedDigest {
				t.Fatalf("ubuntu:24.04 current/pinned digest mismatch: %+v", r)
			}
			sawMatch = true
			continue
		}
		if !r.Drifted {
			t.Fatalf("%s:%s should be reported as drifted: %+v", r.Distro, r.Release, r)
		}
		sawDrift = true
	}
	if !sawMatch || !sawDrift {
		t.Fatalf("expected both a matching and a drifted entry, got sawMatch=%v sawDrift=%v", sawMatch, sawDrift)
	}
}

func TestCheckCatalogReportsPullError(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "pull" {
			return nil, errors.New("pull failed")
		}
		return nil, nil
	}
	results, err := CheckCatalog(context.Background(), CatalogCheckOptions{Backend: "docker", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Error == "" {
			t.Fatalf("expected an error for %s:%s when pull fails: %+v", r.Distro, r.Release, r)
		}
		if r.Drifted {
			t.Fatalf("Drifted should be false when Error is set: %+v", r)
		}
	}
}

func TestCheckCatalogRequiresBackendWithCustomRunner(t *testing.T) {
	called := false
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	_, err := CheckCatalog(context.Background(), CatalogCheckOptions{Runner: runner})
	if err == nil {
		t.Fatal("expected error when backend is unspecified with a custom runner")
	}
	if called {
		t.Fatal("no commands should run when backend resolution fails")
	}
}

func TestDigestFromRepoDigest(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		wantOK   bool
		testName string
	}{
		{"docker.io/library/ubuntu@sha256:abc123", "sha256:abc123", true, "well formed"},
		{"no-at-sign-here", "", false, "missing @"},
	}
	for _, tc := range cases {
		got, ok := digestFromRepoDigest(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("%s: digestFromRepoDigest(%q)=(%q,%v), want (%q,%v)", tc.testName, tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
