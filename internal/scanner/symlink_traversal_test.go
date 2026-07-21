package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestHardwareConfigScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/etc/bluetooth/main.conf", outside)

	report := &model.ScanReport{}
	if err := (HardwareConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	// findHardwareConfigFiles filters the path out entirely (safeStat
	// fails), so no item should be created for it at all.
	for _, item := range report.Items {
		if item.Path == "/etc/bluetooth/main.conf" {
			t.Fatalf("hardware config scanner followed a symlink outside root: %+v", item)
		}
	}
}

func TestSystemConfigScannerDoesNotFollowEscapingSymlinkForSystemdOrCron(t *testing.T) {
	root := t.TempDir()
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/etc/systemd/system/evil.service", outside)
	writeSymlink(t, root, "/etc/cron.d/evil", outside)

	report := &model.ScanReport{}
	if err := (SystemConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, service := range report.Services {
		if service.Path == "/etc/systemd/system/evil.service" || service.Path == "/etc/cron.d/evil" {
			if service.ExecStart != "" || service.Schedule != "" || service.User != "" {
				t.Fatalf("systemd/cron scanner followed a symlink outside root: %+v", service)
			}
		}
	}
}

func TestLanguageScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outsidePkgJSON := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(outsidePkgJSON, []byte(`{"name":"leaked-outside-package","version":"9.9.9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSymlink(t, root, "/usr/local/lib/node_modules/evil/package.json", outsidePkgJSON)

	report := &model.ScanReport{}
	if err := (LanguageScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range report.Languages.NPM {
		if pkg.Name == "leaked-outside-package" {
			t.Fatalf("language scanner followed a symlink outside root: %+v", pkg)
		}
	}
}

func TestDesktopScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() // a directory outside root, for the theme-dir case
	writeSymlink(t, root, "/usr/share/themes/evil", outside)

	report := &model.ScanReport{}
	if err := (DesktopScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, theme := range report.Desktop.Themes {
		if theme == "/usr/share/themes/evil" {
			t.Fatalf("desktop scanner followed a symlink outside root: %+v", report.Desktop.Themes)
		}
	}
}

func TestStatefulDataScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeSymlink(t, root, "/var/lib/redis", outside)

	report := &model.ScanReport{}
	if err := (StatefulDataScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.StatefulData {
		if finding.Path == "/var/lib/redis" {
			t.Fatalf("stateful data scanner followed a symlink outside root: %+v", finding)
		}
	}
}

func TestAptScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", "Package: curl\nStatus: install ok installed\nVersion: 8.0\n\n")
	outside := writeOutsideSecret(t)
	writeSymlink(t, root, "/etc/apt/preferences.d/evil", outside)

	report := &model.ScanReport{}
	if err := (AptScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, item := range report.Items {
		if item.Path == "/etc/apt/preferences.d/evil" {
			t.Fatalf("apt scanner followed a symlink outside root: %+v", item)
		}
	}
}

func TestPackageEcosystemScannerDoesNotFollowEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outsideVersionDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideVersionDir, "INSTALL_RECEIPT.json"), []byte(`{"source":{"tap":"leaked-outside-tap"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/home/linuxbrew/.linuxbrew/Cellar/tool/.keep", "")
	writeSymlink(t, root, "/home/linuxbrew/.linuxbrew/Cellar/tool/9.9.9", outsideVersionDir)

	report := &model.ScanReport{}
	if err := (PackageEcosystemScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range report.Packages {
		for _, v := range pkg.Details {
			if strings.Contains(v, "leaked-outside-tap") {
				t.Fatalf("package ecosystem scanner followed a symlink outside root: %+v", pkg)
			}
		}
	}
}
