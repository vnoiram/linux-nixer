package baseline

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestImportBuildsManifestFromTarFile(t *testing.T) {
	tarBytes := buildTar(t, []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/hostname", content: "myhost\n"},
	})
	tarPath := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(tarPath, tarBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	manifest, err := Import(context.Background(), ImportOptions{Distro: "ubuntu", Release: "24.04", TarPath: tarPath})
	if err != nil {
		t.Fatal(err)
	}

	if manifest.Source != "tar:"+tarPath {
		t.Fatalf("source=%q, want tar:%s", manifest.Source, tarPath)
	}
	found := false
	for _, f := range manifest.Files {
		if f.Path == "/etc/hostname" {
			found = true
			if f.SHA256 == "" {
				t.Fatalf("expected sha256 for /etc/hostname: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("missing /etc/hostname: %+v", manifest.Files)
	}
}

func TestImportDecompressesGzip(t *testing.T) {
	tarBytes := buildTar(t, []tarEntry{
		{name: "etc/hostname", content: "myhost\n"},
	})
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(tarBytes); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "rootfs.tar.gz")
	if err := os.WriteFile(tarPath, gzBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest, err := Import(context.Background(), ImportOptions{Distro: "debian", Release: "12", TarPath: tarPath})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range manifest.Files {
		if f.Path == "/etc/hostname" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing /etc/hostname after gzip decompression: %+v", manifest.Files)
	}
}

func TestImportReadsFromStdin(t *testing.T) {
	tarBytes := buildTar(t, []tarEntry{
		{name: "etc/hostname", content: "myhost\n"},
	})

	manifest, err := Import(context.Background(), ImportOptions{Distro: "ubuntu", Release: "24.04", TarPath: "-", Stdin: bytes.NewReader(tarBytes)})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Source != "tar:stdin" {
		t.Fatalf("source=%q, want tar:stdin", manifest.Source)
	}
	found := false
	for _, f := range manifest.Files {
		if f.Path == "/etc/hostname" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing /etc/hostname from stdin import: %+v", manifest.Files)
	}
}

func TestImportRequiresDistroReleaseAndTar(t *testing.T) {
	cases := []ImportOptions{
		{Release: "24.04", TarPath: "x.tar"},
		{Distro: "ubuntu", TarPath: "x.tar"},
		{Distro: "ubuntu", Release: "24.04"},
	}
	for _, opts := range cases {
		if _, err := Import(context.Background(), opts); err == nil {
			t.Fatalf("expected error for incomplete options: %+v", opts)
		}
	}
}
