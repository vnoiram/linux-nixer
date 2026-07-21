package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

// writeOutsideSecret creates a file outside any --root fixture, containing
// a distinctive marker, for symlink-escape regression tests to check for.
func writeOutsideSecret(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(path, []byte("token=OUTSIDE-ROOT-SECRET-VALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDevOpsConfigScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/home/alice/.kube/config", outside)

	report := &model.ScanReport{}
	if err := (DevOpsConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	// The item is still created (item creation isn't gated on read
	// success), but its Details must not reflect the outside file's
	// content: readLocalDevOpsFile must not have followed the symlink and
	// counted "token=" from it as a secret-refs hit.
	for _, item := range report.Items {
		if item.Path != "/home/alice/.kube/config" {
			continue
		}
		if _, ok := item.Details["secret-refs"]; ok {
			t.Fatalf("devops scanner followed a symlink outside root and read its content: %+v", item)
		}
	}
}

func TestSecretScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/home/alice/.ssh/id_ed25519", outside)

	report := &model.ScanReport{}
	if err := (SecretScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	// addSecretFinding returns early (no finding appended at all) when the
	// path doesn't resolve safely under root.
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/home/alice/.ssh/id_ed25519" {
			t.Fatalf("secret scanner followed a symlink outside root: %+v", finding)
		}
	}
}

func TestBackupConfigScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/home/alice/.config/rclone/rclone.conf", outside)

	report := &model.ScanReport{}
	if err := (BackupConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	// findBackupFiles filters the path out entirely (safeStat fails), so
	// no item should be created for it at all.
	for _, item := range report.Items {
		if item.Path == "/home/alice/.config/rclone/rclone.conf" {
			t.Fatalf("backup scanner followed a symlink outside root: %+v", item)
		}
	}
}

func TestUserConfigScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/home/alice/.gitconfig", outside)

	report := &model.ScanReport{}
	if err := (UserConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	// addUserConfigItemWithDecision returns early (no item at all) when
	// the path doesn't resolve safely under root.
	for _, item := range report.Items {
		if item.Path == "/home/alice/.gitconfig" {
			t.Fatalf("user config scanner followed a symlink outside root: %+v", item)
		}
	}
}
