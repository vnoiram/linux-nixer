package baseline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateSkipsNoisyPathsAndChecksumsFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/hostname", "host\n")
	write(t, root, "var/log/noise.log", "noise\n")

	m, err := Create(context.Background(), "ubuntu", "24.04", root)
	if err != nil {
		t.Fatal(err)
	}
	if m.Checksum == "" {
		t.Fatal("missing manifest checksum")
	}
	if len(m.Files) == 0 {
		t.Fatal("expected baseline files")
	}
	for _, f := range m.Files {
		if f.Path == "/var/log/noise.log" {
			t.Fatal("noisy log path should be skipped")
		}
	}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
