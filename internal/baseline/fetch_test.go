package baseline

import (
	"archive/tar"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	content  string
	linkname string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.content)),
			Linkname: e.linkname,
		}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.content != "" {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchBuildsManifestFromExportedTar(t *testing.T) {
	tarBytes := buildTar(t, []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/hostname", content: "myhost\n"},
		{name: "usr/bin/tool", content: "#!/bin/sh\n", mode: 0o755},
	})

	var calls []string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "export" {
			return tarBytes, nil
		}
		return nil, nil
	}

	manifest, err := Fetch(context.Background(), FetchOptions{Distro: "ubuntu", Release: "24.04", Backend: "docker", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}

	const wantPullRefPrefix = "docker.io/library/ubuntu:24.04@sha256:"
	if !strings.HasPrefix(manifest.Source, "docker:"+wantPullRefPrefix) {
		t.Fatalf("source=%q, want prefix docker:%s", manifest.Source, wantPullRefPrefix)
	}

	paths := map[string]FileEntry{}
	for _, f := range manifest.Files {
		paths[f.Path] = f
	}
	if _, ok := paths["/etc/hostname"]; !ok {
		t.Fatalf("missing /etc/hostname: %+v", manifest.Files)
	}
	if _, ok := paths["/usr/bin/tool"]; !ok {
		t.Fatalf("missing /usr/bin/tool: %+v", manifest.Files)
	}
	if paths["/etc/hostname"].SHA256 == "" {
		t.Fatalf("expected sha256 for /etc/hostname: %+v", paths["/etc/hostname"])
	}

	if len(calls) != 4 {
		t.Fatalf("expected 4 commands (pull/create/export/rm), got %d: %v", len(calls), calls)
	}
	if !strings.HasPrefix(calls[0], "docker pull "+wantPullRefPrefix) {
		t.Fatalf("unexpected first call: %q", calls[0])
	}
	createParts := strings.Fields(calls[1])
	if len(createParts) != 5 || createParts[0] != "docker" || createParts[1] != "create" || createParts[2] != "--name" || !strings.HasPrefix(createParts[4], wantPullRefPrefix) {
		t.Fatalf("unexpected create call: %q", calls[1])
	}
	containerName := createParts[3]
	if calls[2] != "docker export "+containerName {
		t.Fatalf("export call %q does not reference created container %q", calls[2], containerName)
	}
	if calls[3] != "docker rm -f "+containerName {
		t.Fatalf("rm call %q does not reference created container %q", calls[3], containerName)
	}
}

func TestFetchSkipsSymlinksInTar(t *testing.T) {
	tarBytes := buildTar(t, []tarEntry{
		{name: "etc/hostname", content: "myhost\n"},
		{name: "etc/alias", typeflag: tar.TypeSymlink, linkname: "hostname"},
	})
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "export" {
			return tarBytes, nil
		}
		return nil, nil
	}

	manifest, err := Fetch(context.Background(), FetchOptions{Distro: "ubuntu", Release: "24.04", Backend: "docker", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	foundHostname := false
	for _, f := range manifest.Files {
		if f.Path == "/etc/alias" {
			t.Fatalf("symlink entry should not be extracted: %+v", manifest.Files)
		}
		if f.Path == "/etc/hostname" {
			foundHostname = true
		}
	}
	if !foundHostname {
		t.Fatalf("expected /etc/hostname in manifest: %+v", manifest.Files)
	}
}

func TestFetchRequiresBackendWithCustomRunner(t *testing.T) {
	called := false
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	_, err := Fetch(context.Background(), FetchOptions{Distro: "ubuntu", Release: "24.04", Runner: runner})
	if err == nil {
		t.Fatal("expected error when backend is unspecified with a custom runner")
	}
	if called {
		t.Fatal("no commands should run when backend resolution fails")
	}
}

func TestFetchRejectsDistroReleaseNotInCatalog(t *testing.T) {
	called := false
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	_, err := Fetch(context.Background(), FetchOptions{Distro: "alpine", Release: "3.19", Backend: "docker", Runner: runner})
	if err == nil {
		t.Fatal("expected error for a distro/release not in the baseline catalog")
	}
	if called {
		t.Fatal("no commands should run when the distro/release isn't in the catalog")
	}
}

func TestSafeExtractPathContainsTraversalAttempts(t *testing.T) {
	destDir := t.TempDir()
	cases := []string{
		"../../../etc/passwd",
		"/etc/passwd",
		"a/../../b",
		"etc/hostname",
	}
	for _, name := range cases {
		target, ok := safeExtractPath(destDir, name)
		if !ok {
			t.Fatalf("safeExtractPath(%q) rejected unexpectedly", name)
		}
		rel, err := filepath.Rel(destDir, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("safeExtractPath(%q) = %q escapes destDir", name, target)
		}
	}
}
