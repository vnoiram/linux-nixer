package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestAptScannerParsesInstalledPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

Package: removed
Status: deinstall ok config-files
Version: 1.0
`)

	report := &model.ScanReport{}
	if err := (AptScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Packages) != 1 {
		t.Fatalf("packages=%d, want 1", len(report.Packages))
	}
	if report.Packages[0].Name != "curl" || report.Packages[0].NixNames[0] != "curl" {
		t.Fatalf("unexpected package: %+v", report.Packages[0])
	}
}

func TestAptScannerFindsPackageSourcesAndInstallReasons(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

Package: libauto
Status: install ok installed
Version: 1.0

Package: shellcheck
Status: install ok installed
Version: 0.10.0

`)
	write(t, root, "/var/lib/apt/extended_states", `Package: libauto
Architecture: amd64
Auto-Installed: 1

`)
	write(t, root, "/etc/apt/sources.list", "# comment\ndeb http://archive.ubuntu.com/ubuntu noble main\n")
	write(t, root, "/etc/apt/sources.list.d/vendor.sources", "Types: deb\nURIs: https://example.com/apt\nSuites: stable\n")
	write(t, root, "/etc/apt/keyrings/vendor.gpg", "key")
	write(t, root, "/etc/apt/trusted.gpg.d/legacy.gpg", "key")
	write(t, root, "/etc/apt/preferences.d/pin", "Package: *\nPin: origin example.com\n")
	write(t, root, "/etc/apt/apt.conf.d/99local", `APT::Install-Recommends "false";`)

	report := &model.ScanReport{}
	if err := (AptScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	packages := map[string]model.Package{}
	for _, pkg := range report.Packages {
		packages[pkg.Name] = pkg
	}
	if packages["curl"].Source != "dpkg:manual-or-unknown" {
		t.Fatalf("curl source=%q, want manual-or-unknown in %+v", packages["curl"].Source, report.Packages)
	}
	if packages["libauto"].Source != "dpkg:auto-installed" {
		t.Fatalf("libauto source=%q, want auto-installed in %+v", packages["libauto"].Source, report.Packages)
	}
	if len(packages["shellcheck"].NixNames) != 1 || packages["shellcheck"].NixNames[0] != "shellcheck" {
		t.Fatalf("shellcheck nixNames=%v, want [shellcheck] in %+v", packages["shellcheck"].NixNames, report.Packages)
	}
	items := map[string]model.Item{}
	for _, item := range report.Items {
		items[item.Path] = item
	}
	for path, kind := range map[string]string{
		"/etc/apt/sources.list":                  "apt-source",
		"/etc/apt/sources.list.d/vendor.sources": "apt-source",
		"/etc/apt/keyrings/vendor.gpg":           "apt-keyring",
		"/etc/apt/trusted.gpg.d/legacy.gpg":      "apt-keyring",
		"/etc/apt/preferences.d/pin":             "apt-preference",
		"/etc/apt/apt.conf.d/99local":            "apt-config",
	} {
		if items[path].Kind != kind {
			t.Fatalf("item %s kind=%q, want %q in %+v", path, items[path].Kind, kind, report.Items)
		}
	}
	if !strings.Contains(items["/etc/apt/sources.list"].Source, "deb http://archive.ubuntu.com/ubuntu noble main") {
		t.Fatalf("apt source hint missing sanitized source line: %+v", items["/etc/apt/sources.list"])
	}
}

func TestAptInstallReasonUsesAptMarkOnHostRoot(t *testing.T) {
	report := &model.ScanReport{}
	manual, auto, loaded := aptInstallReasonHints(context.Background(), Options{
		Root: "/",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name != "apt-mark" || strings.Join(args, " ") != "showmanual" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("curl\ngit\n"), nil
		},
	}, report)
	if !manual["curl"] || !manual["git"] || len(auto) != 0 || loaded {
		t.Fatalf("unexpected apt-mark hints manual=%+v auto=%+v loaded=%v", manual, auto, loaded)
	}
}

func TestAptScannerUsesSudoFallbackForStatus(t *testing.T) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		t.Skip("host dpkg status is readable; apt sudo fallback path cannot be forced deterministically")
	}
	report := &model.ScanReport{}
	called := false
	err := (AptScanner{}).Scan(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "apt-mark" && strings.Join(args, " ") == "showmanual" {
				return nil, errors.New("apt-mark unavailable")
			}
			called = true
			if name != "sudo" || strings.Join(args, " ") != "cat /var/lib/dpkg/status" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("Package: curl\nStatus: install ok installed\nVersion: 8.0\n\n"), nil
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("sudo fallback runner was not called")
	}
	if len(report.Packages) != 1 || report.Packages[0].Name != "curl" {
		t.Fatalf("unexpected packages: %+v", report.Packages)
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0].Message, "sudo fallback used") {
		t.Fatalf("missing sudo warning: %+v", report.Warnings)
	}
}

func TestReadFileUsesSudoFallback(t *testing.T) {
	report := &model.ScanReport{}
	called := false
	got, err := readFile(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "sudo" || strings.Join(args, " ") != "cat /definitely-missing-linux-nixer-test" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("fallback"), nil
		},
	}, report, "test", "/definitely-missing-linux-nixer-test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fallback" || !called {
		t.Fatalf("fallback got=%q called=%v", got, called)
	}
}

func TestUserScannerAddsGroupsAndSystemHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/passwd", `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/zsh
bob:x:1001:1001:Bob:/home/bob:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
service:x:1200:1200:service:/var/lib/service:/bin/false
`)
	write(t, root, "/etc/group", `root:x:0:
daemon:x:1:
alice:x:1000:
bob:x:1001:
service:x:1200:
sudo:x:27:alice
docker:x:998:alice
video:x:44:alice,bob
`)

	report := &model.ScanReport{}
	if err := (UserScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	users := map[string]model.User{}
	for _, user := range report.Users {
		users[user.Name] = user
	}
	if users["alice"].System || !contains(users["alice"].Groups, "alice") || !contains(users["alice"].Groups, "sudo") || !contains(users["alice"].Groups, "docker") || !contains(users["alice"].Groups, "video") {
		t.Fatalf("alice groups/system unexpected: %+v", users["alice"])
	}
	if !users["bob"].System || !contains(users["bob"].Groups, "video") {
		t.Fatalf("bob should be system due nologin and retain groups: %+v", users["bob"])
	}
	if !users["daemon"].System || !users["service"].System {
		t.Fatalf("daemon/service should be system users: daemon=%+v service=%+v", users["daemon"], users["service"])
	}
	if users["root"].System || !contains(users["root"].Groups, "root") {
		t.Fatalf("root should remain dedicated non-system user with root group: %+v", users["root"])
	}
}

func TestUserScannerContinuesWithoutGroupFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/passwd", "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
	report := &model.ScanReport{}
	if err := (UserScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Users) != 1 || len(report.Users[0].Groups) != 0 {
		t.Fatalf("unexpected users without group file: %+v", report.Users)
	}
}

func TestFilesystemDiffClassifiesSeededRandomLikeApps(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/random-seed-42/tools/fake-elf", append([]byte{0x7f, 'E', 'L', 'F'}, []byte("payload")...), 0o755)
	writeMode(t, root, "/random-seed-42/tools/script.py", []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o755)
	write(t, root, "/random-seed-42/app.desktop", "[Desktop Entry]\nName=Seeded\n")
	write(t, root, "/random-seed-42/seeded.service", "[Service]\nExecStart=/random-seed-42/tools/fake-elf\n")

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/random-seed-42"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]bool{}
	for _, finding := range report.FilesystemDiff {
		cats[finding.Category] = true
	}
	for _, want := range []string{"executable", "script", "desktop-entry", "service"} {
		if !cats[want] {
			t.Fatalf("missing category %q in %+v", want, report.FilesystemDiff)
		}
	}
}

func TestFilesystemDiffAddsMigrationHintsForCommonLocations(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/opt/vendor/bin/app", append([]byte{0x7f, 'E', 'L', 'F'}, []byte("payload")...), 0o755)
	writeMode(t, root, "/usr/local/bin/local-tool", []byte("#!/bin/sh\necho local\n"), 0o755)
	write(t, root, "/srv/app/app.service", "[Service]\nExecStart=/opt/vendor/bin/app\n")
	write(t, root, "/home/alice/.config/tool/config.toml", "theme = 'dark'\n")
	write(t, root, "/home/alice/.ssh/id_ed25519", "PRIVATE KEY\n")
	write(t, root, "/var/lib/postgresql/data/PG_VERSION", "16\n")

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/var/lib/postgresql"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	findings := map[string]model.FileFinding{}
	for _, finding := range report.FilesystemDiff {
		findings[finding.Path] = finding
	}
	for path, category := range map[string]string{
		"/opt/vendor/bin/app":                  "executable",
		"/usr/local/bin/local-tool":            "script",
		"/srv/app/app.service":                 "service",
		"/home/alice/.config/tool/config.toml": "config",
		"/home/alice/.ssh/id_ed25519":          "secret",
	} {
		if findings[path].Category != category {
			t.Fatalf("finding %s category=%q, want %q in %+v", path, findings[path].Category, category, report.FilesystemDiff)
		}
		if findings[path].Reason == "" {
			t.Fatalf("finding %s missing reason: %+v", path, findings[path])
		}
	}
	if !strings.Contains(findings["/opt/vendor/bin/app"].Reason, "/opt") {
		t.Fatalf("opt executable missing location hint: %+v", findings["/opt/vendor/bin/app"])
	}
	if !strings.Contains(findings["/usr/local/bin/local-tool"].Reason, "/usr/local executable path") {
		t.Fatalf("usr local script missing location hint: %+v", findings["/usr/local/bin/local-tool"])
	}
	if findings["/home/alice/.ssh/id_ed25519"].Decision != model.DecisionMigrationNote || !findings["/home/alice/.ssh/id_ed25519"].SecretRisk {
		t.Fatalf("secret should be migration note with secret risk: %+v", findings["/home/alice/.ssh/id_ed25519"])
	}
	if len(report.StatefulData) != 1 || report.StatefulData[0].Path != "/var/lib/postgresql" || report.StatefulData[0].Reason == "" {
		t.Fatalf("unexpected stateful data: %+v", report.StatefulData)
	}
}

func TestStatefulDataScannerFindsCommonRuntimeState(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/redis/dump.rdb", "redis-secret-content")
	write(t, root, "/var/lib/mongodb/WiredTiger", "mongo-data")
	write(t, root, "/var/lib/rabbitmq/mnesia/.keep", "")
	write(t, root, "/var/lib/prometheus/chunks_head/.keep", "")
	write(t, root, "/var/lib/grafana/grafana.db", "grafana")
	write(t, root, "/var/lib/docker/volumes/pgdata/_data/.keep", "")
	write(t, root, "/var/lib/libvirt/images/vm.qcow2", "vm")
	write(t, root, "/srv/app/uploads/avatar.png", "image")

	report := &model.ScanReport{}
	if err := (StatefulDataScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	findings := map[string]model.FileFinding{}
	for _, finding := range report.StatefulData {
		findings[finding.Path] = finding
	}
	for _, path := range []string{
		"/var/lib/redis",
		"/var/lib/mongodb",
		"/var/lib/rabbitmq",
		"/var/lib/prometheus",
		"/var/lib/grafana",
		"/var/lib/docker",
		"/var/lib/libvirt/images",
		"/srv/app/uploads",
	} {
		finding := findings[path]
		if finding.Path == "" {
			t.Fatalf("missing stateful finding %s in %+v", path, report.StatefulData)
		}
		if finding.Category != "stateful-data" || finding.Type != "directory" || finding.Decision != model.DecisionMigrationNote || finding.Reason == "" {
			t.Fatalf("stateful finding not protected: %+v", finding)
		}
		if strings.Contains(finding.Reason, "redis-secret-content") || strings.Contains(finding.Reason, "mongo-data") {
			t.Fatalf("stateful finding leaked raw content: %+v", finding)
		}
	}
}

func TestStatefulDataScannerDeduplicatesFilesystemFindings(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/redis/dump.rdb", "redis")

	report := &model.ScanReport{}
	if err := (StatefulDataScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/var/lib/redis"}}, report); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range report.StatefulData {
		if finding.Path == "/var/lib/redis" && finding.Category == "stateful-data" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("redis stateful finding count=%d, want 1 in %+v", count, report.StatefulData)
	}
}

func TestFilesystemDiffUsesBaselineManifest(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/usr/local/bin/same", []byte("#!/bin/sh\necho same\n"), 0o755)
	writeMode(t, root, "/usr/local/bin/new", []byte("#!/bin/sh\necho new\n"), 0o755)
	baseline := filepath.Join(root, "baseline.json")
	sum := sha256Hex(t, filepath.Join(root, "usr/local/bin/same"))
	if err := os.WriteFile(baseline, []byte(`{"files":[{"path":"/usr/local/bin/same","type":"script","mode":"-rwxr-xr-x","size":20,"sha256":"`+sum+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	report := &model.ScanReport{}
	err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, BaselineID: baseline, Includes: []string{"/usr/local/bin"}}, report)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/usr/local/bin/same" {
			t.Fatalf("unchanged baseline file should be skipped: %+v", report.FilesystemDiff)
		}
	}
	foundNew := false
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/usr/local/bin/new" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Fatalf("new file missing: %+v", report.FilesystemDiff)
	}
}

func TestFilesystemDiffDetectsArbitraryBaselineChanges(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/usr/local/bin/unchanged", []byte("#!/bin/sh\necho same\n"), 0o755)
	writeMode(t, root, "/usr/local/bin/new", []byte("#!/bin/sh\necho new\n"), 0o755)
	writeMode(t, root, "/usr/local/bin/content-changed", []byte("#!/bin/sh\necho after\n"), 0o755)
	writeMode(t, root, "/usr/local/bin/perm-changed", []byte("#!/bin/sh\necho perm\n"), 0o755)

	unchangedSum := sha256Hex(t, filepath.Join(root, "usr/local/bin/unchanged"))
	permSum := sha256Hex(t, filepath.Join(root, "usr/local/bin/perm-changed"))

	baseline := filepath.Join(root, "baseline.json")
	baselineJSON := `{"files":[` +
		`{"path":"/usr/local/bin/unchanged","type":"script","mode":"-rwxr-xr-x","size":20,"sha256":"` + unchangedSum + `"},` +
		`{"path":"/usr/local/bin/content-changed","type":"script","mode":"-rwxr-xr-x","size":21,"sha256":"deadbeef"},` +
		`{"path":"/usr/local/bin/perm-changed","type":"script","mode":"-rw-r--r--","size":21,"sha256":"` + permSum + `"}` +
		`]}`
	if err := os.WriteFile(baseline, []byte(baselineJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	report := &model.ScanReport{}
	if err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root, BaselineID: baseline, Includes: []string{"/usr/local/bin"}}, report); err != nil {
		t.Fatal(err)
	}

	reported := map[string]bool{}
	for _, finding := range report.FilesystemDiff {
		reported[finding.Path] = true
	}

	if reported["/usr/local/bin/unchanged"] {
		t.Fatalf("unchanged file should be skipped: %+v", report.FilesystemDiff)
	}
	for _, path := range []string{"/usr/local/bin/new", "/usr/local/bin/content-changed", "/usr/local/bin/perm-changed"} {
		if !reported[path] {
			t.Fatalf("%s should be reported as changed: %+v", path, report.FilesystemDiff)
		}
	}
}

func TestSecretScannerFindsCommonCredentialLocations(t *testing.T) {
	root := t.TempDir()
	writeMode(t, root, "/home/alice/.ssh/id_ed25519", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-value\n"), 0o600)
	writeMode(t, root, "/home/alice/.aws/credentials", []byte("[default]\naws_secret_access_key=secret-value\n"), 0o600)
	writeMode(t, root, "/home/alice/.docker/config.json", []byte(`{"auths":{"example.com":{"auth":"secret-value"}}}`), 0o600)
	writeMode(t, root, "/home/alice/.kube/config", []byte("users:\n- token: secret-value\n"), 0o600)
	writeMode(t, root, "/etc/NetworkManager/system-connections/home.nmconnection", []byte("[wifi-security]\npsk=secret-value\n"), 0o600)
	writeMode(t, root, "/etc/app/config.conf", []byte("mode=prod\n"), 0o644)

	report := &model.ScanReport{}
	if err := (SecretScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	findings := map[string]model.FileFinding{}
	for _, finding := range report.FilesystemDiff {
		findings[finding.Path] = finding
	}
	for _, path := range []string{
		"/home/alice/.ssh/id_ed25519",
		"/home/alice/.aws/credentials",
		"/home/alice/.docker/config.json",
		"/home/alice/.kube/config",
		"/etc/NetworkManager/system-connections/home.nmconnection",
	} {
		finding, ok := findings[path]
		if !ok {
			t.Fatalf("missing secret finding %s in %+v", path, report.FilesystemDiff)
		}
		if finding.Category != "secret" || !finding.SecretRisk || finding.Decision != model.DecisionMigrationNote {
			t.Fatalf("secret finding not protected: %+v", finding)
		}
		if strings.Contains(finding.Reason, "secret-value") {
			t.Fatalf("secret finding leaked raw value in reason: %+v", finding)
		}
		if finding.SHA256 == "" || finding.Mode == "" || finding.Size == 0 {
			t.Fatalf("secret finding missing metadata: %+v", finding)
		}
	}
	if _, ok := findings["/etc/app/config.conf"]; ok {
		t.Fatalf("non-secret config should not be a secret finding: %+v", findings["/etc/app/config.conf"])
	}
}

func TestSecretScannerDeepFindsProjectEnvFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/project/.env", "API_TOKEN=secret-value\n")

	shallow := &model.ScanReport{}
	if err := (SecretScanner{}).Scan(context.Background(), Options{Root: root}, shallow); err != nil {
		t.Fatal(err)
	}
	for _, finding := range shallow.FilesystemDiff {
		if finding.Path == "/home/alice/project/.env" {
			t.Fatalf("project .env should require deep scan: %+v", shallow.FilesystemDiff)
		}
	}

	deep := &model.ScanReport{}
	if err := (SecretScanner{}).Scan(context.Background(), Options{Root: root, Deep: true}, deep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range deep.FilesystemDiff {
		if finding.Path == "/home/alice/project/.env" && finding.SecretRisk {
			found = true
		}
	}
	if !found {
		t.Fatalf("deep scan missing project .env: %+v", deep.FilesystemDiff)
	}
}

func TestSecretScannerDoesNotDuplicateFilesystemSecretFindings(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.ssh/id_ed25519", "PRIVATE KEY\n")

	report := &model.ScanReport{}
	if err := (SecretScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if err := (FilesystemDiffScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/home/alice/.ssh/id_ed25519" && finding.Category == "secret" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("secret finding count=%d, want 1 in %+v", count, report.FilesystemDiff)
	}
}

func TestDevOpsConfigScannerMarksSecretRiskConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "users:\n- token: super-secret\n")
	report := &model.ScanReport{}
	if err := (DevOpsConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) == 0 {
		t.Fatal("expected config item")
	}
	if report.Items[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("decision=%q, want migration-note", report.Items[0].Decision)
	}
	if len(report.Warnings) == 0 || report.Warnings[0].Source != "devops-config" || !strings.Contains(report.Warnings[0].Message, "secret-risk") {
		t.Fatalf("expected secret warning, got %+v", report.Warnings)
	}
}

func TestExistsWithSudoUsesSudoFallback(t *testing.T) {
	report := &model.ScanReport{}
	got := existsWithSudo(context.Background(), Options{
		Root:    "/",
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "sudo" && strings.Join(args, " ") == "test -e /definitely-missing-linux-nixer-test" {
				return []byte{}, nil
			}
			return nil, errors.New("not found")
		},
	}, report, "test", "/definitely-missing-linux-nixer-test")
	if !got {
		t.Fatal("expected sudo fallback existence check to succeed")
	}
}

func TestSudoFallbackDisabledForMountedRootfs(t *testing.T) {
	root := t.TempDir()
	report := &model.ScanReport{}
	called := false
	_, err := readFile(context.Background(), Options{
		Root:    root,
		UseSudo: true,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return []byte("secret"), nil
		},
	}, report, "test", "/missing")
	if err == nil {
		t.Fatal("expected normal read error")
	}
	if called {
		t.Fatal("sudo runner should not be called for mounted rootfs")
	}
}

func TestDevOpsConfigScannerFindsProviderConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.kube/config", "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: https://k8s.example.test\ncontexts:\n- name: prod\n  context:\n    namespace: default\nusers:\n- name: alice\n  user:\n    token: super-secret\n    exec:\n      command: oidc-login\n")
	write(t, root, "/home/alice/.docker/config.json", `{"auths":{"registry.example.test":{"auth":"secret-value"}},"credsStore":"pass","credHelpers":{"ghcr.io":"pass"},"currentContext":"desktop-linux","plugins":{"scan":{}}}`)
	write(t, root, "/home/alice/.config/helm/repositories.yaml", "repositories:\n- name: stable\n  url: https://charts.example.test\n  password: super-secret\n- name: oci\n  url: oci://registry.example.test/charts\n")
	write(t, root, "/home/alice/.terraformrc", "credentials \"app.terraform.io\" { token = \"super-secret\" }\ncredentials_helper \"helper\" {}\nplugin_cache_dir = \"/home/alice/.terraform.d/plugin-cache\"\nprovider_installation {}\n")
	write(t, root, "/home/alice/.aws/config", "[default]\nregion=us-east-1\n[profile prod]\nregion=ap-northeast-1\nsso_start_url=https://example.test/start\nsso_region=us-east-1\n")
	write(t, root, "/home/alice/.config/gcloud/configurations/config_default", "[core]\nproject = secret-project\naccount = alice@example.test\n[compute]\nzone = asia-northeast1-a\n")
	write(t, root, "/home/alice/.azure/config", "[cloud]\nname = AzureCloud\n[defaults]\nsubscription = secret-subscription\ntenant = secret-tenant\n")
	write(t, root, "/home/alice/app/.github/workflows/ci.yml", "on: [push, pull_request]\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n")
	write(t, root, "/home/alice/app/.gitlab-ci.yml", "stages:\n  - test\ntest:\n  stage: test\n  script: echo $DEPLOY_TOKEN\n")
	write(t, root, "/srv/app/Jenkinsfile", "pipeline { agent any stages { stage('Deploy') { steps { sh 'deploy' } } } environment { TOKEN='secret-value' } }\n")
	write(t, root, "/srv/app/scripts/deploy-prod.sh", "#!/bin/sh\nrelease_app --token=secret-value\n")
	write(t, root, "/srv/app/Makefile", "build:\n\tgo build ./...\ndeploy:\n\t./scripts/deploy-prod.sh\n")

	report := &model.ScanReport{}
	if err := (DevOpsConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Item{}
	for _, item := range report.Items {
		seen[item.Path] = item
	}
	for _, path := range []string{
		"/home/alice/.kube/config",
		"/home/alice/.docker/config.json",
		"/home/alice/.config/helm/repositories.yaml",
		"/home/alice/.terraformrc",
		"/home/alice/.config/gcloud/configurations/config_default",
		"/home/alice/.azure/config",
	} {
		if seen[path].Decision != model.DecisionMigrationNote {
			t.Fatalf("path %s decision=%q, want migration-note in %+v", path, seen[path].Decision, report.Items)
		}
	}
	if seen["/home/alice/.aws/config"].Decision != model.DecisionCandidate {
		t.Fatalf("aws config should remain candidate in %+v", report.Items)
	}
	kube := seen["/home/alice/.kube/config"]
	if kube.Details["contexts"] != "1" || kube.Details["clusters"] != "1" || kube.Details["users"] != "1" || kube.Details["current-context"] != "present" || kube.Details["namespace"] != "present" || kube.Details["exec-auth"] != "present" || kube.Details["secret-refs"] != "1" {
		t.Fatalf("kubernetes config details missing: %+v", kube)
	}
	docker := seen["/home/alice/.docker/config.json"]
	if docker.Details["registries"] != "1" || docker.Details["credential-store"] != "present" || docker.Details["credential-helpers"] != "1" || docker.Details["current-context"] != "present" || docker.Details["plugins"] != "1" || docker.Details["secret-refs"] != "1" {
		t.Fatalf("docker client details missing: %+v", docker)
	}
	helm := seen["/home/alice/.config/helm/repositories.yaml"]
	if helm.Details["repositories"] != "2" || helm.Details["repository-schemes"] != "https,oci" || helm.Details["secret-refs"] != "1" {
		t.Fatalf("helm details missing: %+v", helm)
	}
	tf := seen["/home/alice/.terraformrc"]
	if tf.Details["credential-hosts"] != "1" || tf.Details["credential-helper"] != "present" || tf.Details["plugin-cache"] != "present" || tf.Details["provider-installation"] != "present" || tf.Details["secret-refs"] != "1" {
		t.Fatalf("terraform details missing: %+v", tf)
	}
	aws := seen["/home/alice/.aws/config"]
	if aws.Details["profiles"] != "2" || aws.Details["regions"] != "2" || aws.Details["sso-settings"] != "2" {
		t.Fatalf("aws details missing: %+v", aws)
	}
	gcloud := seen["/home/alice/.config/gcloud/configurations/config_default"]
	if gcloud.Details["sections"] != "2" || gcloud.Details["properties"] != "3" || gcloud.Details["project"] != "present" || gcloud.Details["account"] != "present" {
		t.Fatalf("gcloud details missing: %+v", gcloud)
	}
	azure := seen["/home/alice/.azure/config"]
	if azure.Details["sections"] != "2" || azure.Details["settings"] != "3" || azure.Details["cloud"] != "present" || azure.Details["subscription"] != "present" || azure.Details["tenant"] != "present" {
		t.Fatalf("azure details missing: %+v", azure)
	}
	gha := seen["/home/alice/app/.github/workflows/ci.yml"]
	if gha.Kind != "cicd-config" || gha.Reason != "github actions workflow" || gha.Details["jobs"] != "1" || gha.Details["uses"] != "1" || gha.Details["secret-refs"] != "1" || gha.Details["triggers"] != "pull_request,push" {
		t.Fatalf("github actions details missing: %+v", gha)
	}
	gitlab := seen["/home/alice/app/.gitlab-ci.yml"]
	if gitlab.Kind != "cicd-config" || gitlab.Reason != "gitlab ci pipeline" || gitlab.Details["stages"] == "" || gitlab.Details["secret-refs"] != "1" {
		t.Fatalf("gitlab ci details missing: %+v", gitlab)
	}
	jenkins := seen["/srv/app/Jenkinsfile"]
	if jenkins.Kind != "cicd-config" || jenkins.Details["stages"] != "1" || jenkins.Details["agents"] != "1" || jenkins.Details["secret-refs"] != "1" {
		t.Fatalf("jenkins details missing: %+v", jenkins)
	}
	deploy := seen["/srv/app/scripts/deploy-prod.sh"]
	if deploy.Kind != "cicd-config" || deploy.Details["shebang"] != "/bin/sh" || !strings.Contains(deploy.Details["targets"], "release") || deploy.Details["secret-refs"] != "1" {
		t.Fatalf("deploy script details missing: %+v", deploy)
	}
	makefile := seen["/srv/app/Makefile"]
	if makefile.Kind != "cicd-config" || !strings.Contains(makefile.Details["targets"], "deploy") || !strings.Contains(makefile.Details["targets"], "build") {
		t.Fatalf("makefile automation details missing: %+v", makefile)
	}
	for _, item := range []model.Item{kube, docker, helm, tf, aws, gcloud, azure, gha, gitlab, jenkins, deploy, makefile} {
		for _, value := range item.Details {
			for _, leaked := range []string{"secret-value", "super-secret", "DEPLOY_TOKEN", "k8s.example.test", "registry.example.test", "charts.example.test", "secret-project", "alice@example.test", "secret-subscription", "secret-tenant"} {
				if strings.Contains(value, leaked) {
					t.Fatalf("devops details leaked %q in %+v", leaked, item)
				}
			}
		}
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected secret-risk warnings, got %+v", report.Warnings)
	}
}

func TestProjectConfigScannerFindsProjectFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/project/package.json", "{}")
	write(t, root, "/home/alice/project/pyproject.toml", "[project]\nname='demo'\n")
	write(t, root, "/home/alice/project/requirements.txt", "ruff\n")
	write(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")
	write(t, root, "/home/alice/project/Cargo.toml", "[package]\n")
	write(t, root, "/home/alice/project/flake.nix", "{}")
	write(t, root, "/home/alice/project/.devcontainer/devcontainer.json", "{}")
	write(t, root, "/srv/app/package.json", "{}")
	write(t, root, "/srv/app/pyproject.toml", "[project]\n")
	write(t, root, "/srv/app/go.mod", "module example.com/app\n")
	write(t, root, "/srv/app/Cargo.toml", "[package]\n")
	write(t, root, "/srv/app/flake.nix", "{}")
	write(t, root, "/home/alice/project/.envrc", "use flake\n")
	write(t, root, "/home/alice/.gitconfig", "[user]\nname = Alice\n")
	write(t, root, "/etc/udev/rules.d/99-device.rules", `SUBSYSTEM=="usb"`)

	report := &model.ScanReport{}
	if err := (ProjectConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Decision{}
	for _, item := range report.Items {
		seen[item.Path] = item.Decision
	}
	for _, path := range []string{
		"/home/alice/project/package.json",
		"/home/alice/project/pyproject.toml",
		"/home/alice/project/requirements.txt",
		"/home/alice/project/go.mod",
		"/home/alice/project/Cargo.toml",
		"/home/alice/project/flake.nix",
		"/home/alice/project/.devcontainer/devcontainer.json",
		"/srv/app/package.json",
		"/srv/app/pyproject.toml",
		"/srv/app/go.mod",
		"/srv/app/Cargo.toml",
		"/srv/app/flake.nix",
	} {
		if seen[path] != model.DecisionCandidate {
			t.Fatalf("missing project config %s in %+v", path, report.Items)
		}
	}
	for _, path := range []string{"/home/alice/project/.envrc", "/home/alice/.gitconfig", "/etc/udev/rules.d/99-device.rules"} {
		if _, ok := seen[path]; ok {
			t.Fatalf("non-project config %s should not be handled by ProjectConfigScanner, got %+v", path, report.Items)
		}
	}
}

func TestDefaultRegistryUsesDedicatedConfigScanners(t *testing.T) {
	reg := DefaultRegistry()
	names := map[string]bool{}
	order := map[string]int{}
	for i, scanner := range reg.scanners {
		names[scanner.Name()] = true
		order[scanner.Name()] = i
	}
	for _, want := range []string{"system-config", "devops-config", "project-config", "user-config", "desktop", "hardware-config", "secrets", "stateful-data", "backup-config"} {
		if !names[want] {
			t.Fatalf("default registry missing %q in %+v", want, names)
		}
	}
	if order["secrets"] >= order["filesystem-diff"] {
		t.Fatalf("secrets scanner should run before filesystem-diff: %+v", order)
	}
	if order["stateful-data"] >= order["filesystem-diff"] {
		t.Fatalf("stateful scanner should run before filesystem-diff: %+v", order)
	}
	if order["backup-config"] >= order["filesystem-diff"] || order["stateful-data"] >= order["backup-config"] {
		t.Fatalf("backup scanner should run after stateful data and before filesystem-diff: %+v", order)
	}
	if order["hardware-config"] >= order["filesystem-diff"] {
		t.Fatalf("hardware scanner should run before filesystem-diff: %+v", order)
	}
	if names["config"] {
		t.Fatalf("default registry should not include legacy config scanner: %+v", names)
	}
}

func TestHardwareConfigScannerFindsPeripheralConfigsSafely(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/cups/printers.conf", "<Printer Office>\nDeviceURI ipp://user:secret@example.test/printers/office\n</Printer>\nDefaultPrinter Office\n")
	write(t, root, "/etc/cups/ppd/Office.ppd", "*NickName: Office Raw Secret\n")
	write(t, root, "/etc/bluetooth/main.conf", "[General]\nDiscoverableTimeout = 60\n")
	write(t, root, "/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info", "[General]\nName=Keyboard\nClass=0x002540\nTrusted=true\nPaired=true\nKey=raw-pairing-secret\n")
	write(t, root, "/etc/sane.d/dll.conf", "net\nepson2\n# disabled\n")
	write(t, root, "/etc/pipewire/pipewire.conf", "[context.properties]\ndefault.clock.rate = 48000\n")
	write(t, root, "/home/alice/.asoundrc", "pcm.!default { type hw card 0 }\n")
	write(t, root, "/etc/fprintd.conf", "[net.reactivated.Fprint]\n")
	write(t, root, "/etc/u2f_mappings", "alice:secret-u2f-mapping\n")
	write(t, root, "/etc/pcsc/reader.conf", "FRIENDLYNAME reader\n")
	write(t, root, "/etc/fwupd/daemon.conf", "[fwupd]\nDisabledDevices=secret-device\n")
	write(t, root, "/etc/tlp.conf", "TLP_ENABLE=1\n")
	write(t, root, "/etc/keyd/default.conf", "[ids]\n*\n[main]\ncapslock = esc\n")
	write(t, root, "/home/alice/.config/xremap/config.yml", "modmap:\n  - name: demo\n")

	report := &model.ScanReport{}
	if err := (HardwareConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	items := map[string]model.Item{}
	for _, item := range report.Items {
		items[item.Path] = item
		if item.Kind != "hardware-config" {
			t.Fatalf("unexpected item kind: %+v", item)
		}
		if item.Decision != model.DecisionMigrationNote {
			t.Fatalf("hardware item should be migration note: %+v", item)
		}
	}
	for _, path := range []string{
		"/etc/cups/printers.conf",
		"/etc/cups/ppd/Office.ppd",
		"/var/lib/bluetooth/AA:BB:CC:DD:EE:FF/11:22:33:44:55:66/info",
		"/etc/sane.d/dll.conf",
		"/etc/pipewire/pipewire.conf",
		"/etc/u2f_mappings",
		"/etc/tlp.conf",
		"/etc/keyd/default.conf",
	} {
		if _, ok := items[path]; !ok {
			t.Fatalf("missing hardware item %s in %+v", path, report.Items)
		}
	}
	if got := items["/etc/cups/printers.conf"].Details["device-uri-schemes"]; got != "ipp" {
		t.Fatalf("device-uri-schemes=%q, want ipp in %+v", got, items["/etc/cups/printers.conf"])
	}
	if items["/etc/cups/printers.conf"].Details["printers"] != "1" || items["/etc/cups/printers.conf"].Details["defaults"] != "1" {
		t.Fatalf("unexpected cups details: %+v", items["/etc/cups/printers.conf"])
	}
	if items["/etc/sane.d/dll.conf"].Details["enabled-backends"] != "2" || items["/etc/sane.d/dll.conf"].Details["network-backend"] != "present" {
		t.Fatalf("unexpected sane details: %+v", items["/etc/sane.d/dll.conf"])
	}
	if items["/etc/u2f_mappings"].Details["mappings"] != "1" || items["/etc/u2f_mappings"].Details["manual-enrollment"] != "recommended" {
		t.Fatalf("unexpected u2f details: %+v", items["/etc/u2f_mappings"])
	}
	for _, item := range report.Items {
		for _, value := range item.Details {
			for _, leaked := range []string{"user:secret", "raw-pairing-secret", "secret-u2f-mapping", "AA:BB:CC", "11:22:33"} {
				if strings.Contains(value, leaked) {
					t.Fatalf("hardware scanner leaked %q in %+v", leaked, item)
				}
			}
		}
	}
}

func TestBackupConfigScannerFindsBackupAndSyncConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.config/rclone/rclone.conf", "[remote]\ntype = s3\naccess_key_id = AKIASECRET\nsecret_access_key = raw-secret\n")
	write(t, root, "/home/alice/.config/syncthing/config.xml", "<configuration><folder id=\"docs\"></folder><device id=\"abc\"></device></configuration>\n")
	write(t, root, "/etc/restic.env", "RESTIC_REPOSITORY=s3:sensitive\nRESTIC_PASSWORD=raw-secret\n")
	write(t, root, "/etc/systemd/system/restic-backup.service", "[Service]\nExecStart=/usr/bin/restic backup /srv --password-file /etc/restic-password\n")
	write(t, root, "/etc/systemd/system/restic-backup.timer", "[Timer]\nOnCalendar=daily\n")
	write(t, root, "/etc/cron.d/rclone-sync", "15 3 * * * root rclone sync /srv remote:backup --token raw-secret\n")

	report := &model.ScanReport{}
	if err := (BackupConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Item{}
	for _, item := range report.Items {
		seen[item.Path] = item
	}
	rclone := seen["/home/alice/.config/rclone/rclone.conf"]
	if rclone.Kind != "backup-config" || rclone.Decision != model.DecisionMigrationNote || rclone.Details["tool"] != "rclone" || rclone.Details["remote-types"] != "s3" || rclone.Details["secret-refs"] != "2" {
		t.Fatalf("rclone details missing: %+v", rclone)
	}
	syncthing := seen["/home/alice/.config/syncthing/config.xml"]
	if syncthing.Details["tool"] != "syncthing" || syncthing.Details["folders"] != "1" || syncthing.Details["devices"] != "1" {
		t.Fatalf("syncthing details missing: %+v", syncthing)
	}
	restic := seen["/etc/restic.env"]
	if restic.Details["tool"] != "restic" || restic.Details["repositories"] != "1" || restic.Details["secret-refs"] != "1" {
		t.Fatalf("restic config details unsafe or missing: %+v", restic)
	}
	job := seen["/etc/systemd/system/restic-backup.service"]
	if job.Reason != "backup or sync job" || job.Details["tools"] != "restic" || job.Details["secret-refs"] != "1" {
		t.Fatalf("systemd backup job details missing: %+v", job)
	}
	timer := seen["/etc/systemd/system/restic-backup.timer"]
	if timer.Details["tools"] != "restic" || timer.Details["schedule"] != "OnCalendar=daily" {
		t.Fatalf("systemd backup timer details missing: %+v", timer)
	}
	cron := seen["/etc/cron.d/rclone-sync"]
	if cron.Details["tools"] != "rclone" || cron.Details["schedule"] != "15 3 * * *" || cron.Details["secret-refs"] != "1" {
		t.Fatalf("cron backup job details missing: %+v", cron)
	}
	for _, item := range report.Items {
		for _, value := range item.Details {
			if strings.Contains(value, "raw-secret") || strings.Contains(value, "AKIASECRET") {
				t.Fatalf("backup details leaked secret in %+v", item)
			}
		}
	}
}

func TestGitScannerFindsSourceMetadataAndHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/app/.git/config", "[remote \"origin\"]\n  url = https://example.com/app.git\n")
	write(t, root, "/home/alice/app/.git/HEAD", "ref: refs/heads/main\n")
	write(t, root, "/home/alice/app/.git/refs/heads/main", "abc123\n")
	write(t, root, "/home/alice/app/.gitmodules", "[submodule \"lib\"]\n")
	write(t, root, "/home/alice/app/flake.nix", "{}")
	write(t, root, "/home/alice/app/shell.nix", "{}")
	write(t, root, "/home/alice/app/justfile", "build:\n")
	write(t, root, "/home/alice/app/Taskfile.yml", "version: '3'\n")
	write(t, root, "/home/alice/app/docker-compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/compose.yaml", "services: {}\n")
	write(t, root, "/home/alice/app/.git/MERGE_HEAD", "def456\n")

	write(t, root, "/opt/tool/.git/config", "[remote \"origin\"]\n  url = git@example.com:tool.git\n")
	write(t, root, "/opt/tool/.git/HEAD", "deadbeef\n")
	write(t, root, "/opt/tool/Makefile", "all:\n")

	write(t, root, "/custom/source/.git/config", "[remote \"origin\"]\n  url = https://example.com/custom.git\n")
	write(t, root, "/custom/source/.git/HEAD", "ref: refs/heads/dev\n")
	write(t, root, "/custom/source/.git/refs/heads/dev", "feedface\n")
	write(t, root, "/custom/source/package.json", "{}")

	report := &model.ScanReport{}
	if err := (GitScanner{}).Scan(context.Background(), Options{Root: root, Includes: []string{"/custom"}}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.GitSource{}
	for _, source := range report.GitSources {
		seen[source.Path] = source
	}
	app := seen["/home/alice/app"]
	if app.Remote != "https://example.com/app.git" || app.Commit != "abc123" || !app.Dirty {
		t.Fatalf("unexpected app git source: %+v", app)
	}
	for _, want := range []string{"branch:main", "submodules", "flake.nix", "shell.nix", "justfile", "Taskfile.yml", "docker-compose.yml", "compose.yaml"} {
		if !contains(app.Build, want) {
			t.Fatalf("app missing build hint %q in %+v", want, app.Build)
		}
	}
	tool := seen["/opt/tool"]
	if tool.Remote != "git@example.com:tool.git" || tool.Commit != "deadbeef" || tool.Dirty {
		t.Fatalf("unexpected tool git source: %+v", tool)
	}
	if !contains(tool.Build, "Makefile") {
		t.Fatalf("tool missing Makefile hint: %+v", tool.Build)
	}
	custom := seen["/custom/source"]
	if custom.Remote != "https://example.com/custom.git" || custom.Commit != "feedface" || !contains(custom.Build, "branch:dev") || !contains(custom.Build, "package.json") {
		t.Fatalf("unexpected custom git source: %+v", custom)
	}
}

func TestSystemConfigScannerFindsOperationalConfigsAndServices(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/fstab", "UUID=demo / ext4 defaults 0 1\n")
	write(t, root, "/etc/hosts", "127.0.0.1 localhost\n")
	write(t, root, "/etc/sudoers", "root ALL=(ALL) ALL\n%sudo ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n@includedir /etc/sudoers.d\n")
	write(t, root, "/etc/sudoers.d/admins", "%admin ALL=(ALL) ALL\n")
	write(t, root, "/etc/login.defs", "UID_MIN 1000\nUID_MAX 60000\nPASS_MAX_DAYS 90\nUMASK 027\nENCRYPT_METHOD SHA512\n")
	write(t, root, "/etc/default/useradd", "SHELL=/bin/bash\nCREATE_HOME=yes\n")
	write(t, root, "/etc/adduser.conf", "DSHELL=/bin/zsh\nFIRST_UID=1000\nLAST_UID=29999\n")
	write(t, root, "/etc/locale.conf", "LANG=en_US.UTF-8\n")
	write(t, root, "/etc/timezone", "UTC\n")
	write(t, root, "/etc/ssh/sshd_config", "Port 2222\nPermitRootLogin no\nPasswordAuthentication no\n")
	write(t, root, "/etc/ssh/ssh_config", "Host *\n  ForwardAgent no\n  ProxyJump bastion\n")
	write(t, root, "/etc/sysctl.conf", "vm.swappiness=10\n")
	write(t, root, "/etc/nftables.conf", "table inet filter {\nchain input {\n tcp dport 22 accept\n}\n}\n")
	write(t, root, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
	write(t, root, "/etc/default/ufw", "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n")
	write(t, root, "/etc/netplan/01-net.yaml", "network:\n  renderer: NetworkManager\n  ethernets:\n    enp1s0:\n      dhcp4: true\n      nameservers:\n        addresses: [1.1.1.1]\n")
	write(t, root, "/etc/NetworkManager/NetworkManager.conf", "[main]\n")
	write(t, root, "/etc/NetworkManager/system-connections/home.nmconnection", "[connection]\nid=home\ntype=wifi\ninterface-name=wlp1s0\nautoconnect=true\n[wifi-security]\npsk=secret\n")
	write(t, root, "/etc/resolv.conf", "nameserver 1.1.1.1\nsearch lan example.test\n")
	write(t, root, "/etc/systemd/resolved.conf", "[Resolve]\nDNS=9.9.9.9\nDomains=~corp.example\n")
	write(t, root, "/etc/sysctl.d/99-local.conf", "fs.inotify.max_user_watches=1\n")
	write(t, root, "/etc/modprobe.d/local.conf", "options test value=1\n")
	write(t, root, "/etc/udev/rules.d/99-device.rules", `SUBSYSTEM=="usb"`)
	write(t, root, "/etc/pam.d/sshd", "auth required pam_faillock.so deny=3 secret=hidden\nauth required pam_u2f.so\nsession optional pam_systemd.so\n")
	write(t, root, "/etc/security/limits.d/audio.conf", "@audio - rtprio 95\n")
	write(t, root, "/etc/polkit-1/rules.d/49-admin.rules", `polkit.addAdminRule(function(action, subject) { return ["unix-group:sudo"]; });`)
	write(t, root, "/usr/local/share/polkit-1/rules.d/50-wheel.rules", `polkit.addRule(function(action, subject) { return polkit.Result.YES; });`)
	write(t, root, "/etc/fail2ban/jail.local", "[sshd]\nenabled = true\nmaxretry = 5\nbantime = 1h\n")
	write(t, root, "/etc/fail2ban/jail.d/nginx.conf", "[nginx-http-auth]\nenabled = true\n")
	write(t, root, "/etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\nmax_log_file = 16\n")
	write(t, root, "/etc/audit/rules.d/hardening.rules", "-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S execve -k exec\n")
	write(t, root, "/etc/apparmor.d/usr.bin.demo", "#include <tunables/global>\nprofile demo /usr/bin/demo {\n  capability net_bind_service,\n}\n")
	write(t, root, "/etc/apparmor.d/local/usr.bin.demo", "capability dac_override,\n")
	write(t, root, "/etc/wireguard/wg0.conf", "[Interface]\nPrivateKey = raw-private\nDNS = 1.1.1.1\n[Peer]\nPublicKey = peer\nPresharedKey = raw-psk\nEndpoint = vpn.example:51820\nAllowedIPs = 10.0.0.0/24, ::/0\n")
	write(t, root, "/etc/openvpn/client.conf", "client\nremote vpn.example 1194\nredirect-gateway def1\nauth-user-pass /etc/openvpn/secret\n")
	write(t, root, "/etc/logrotate.d/app", "/var/log/app/*.log {}\n")
	write(t, root, "/etc/nginx/sites-enabled/app", "server {}\n")
	write(t, root, "/etc/apache2/sites-enabled/app.conf", "<VirtualHost *:80>\n")
	write(t, root, "/etc/systemd/system/custom.service", `[Unit]
Description=Custom app
[Service]
User=app
WorkingDirectory=/srv/app
EnvironmentFile=-/etc/default/custom
ExecStart=/opt/vendor/bin/app --token=super-secret
[Install]
WantedBy=multi-user.target
`)
	write(t, root, "/etc/systemd/system/custom.timer", "[Unit]\nDescription=Custom timer\n[Timer]\nOnCalendar=daily\n")
	write(t, root, "/home/alice/.config/systemd/user/user.service", "[Unit]\nDescription=User app\n[Service]\nExecStart=/home/alice/bin/app\n")
	write(t, root, "/etc/cron.d/job", "15 2 * * * root /usr/local/bin/job\n")
	write(t, root, "/var/spool/cron/crontabs/alice", "*/5 * * * * /home/alice/bin/task\n")

	report := &model.ScanReport{}
	if err := (SystemConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Item{}
	for _, item := range report.Items {
		seen[item.Path] = item
	}
	for path, reason := range map[string]string{
		"/etc/fstab":                                               "filesystem mount configuration",
		"/etc/hosts":                                               "system configuration",
		"/etc/sudoers":                                             "auth and security configuration",
		"/etc/sudoers.d/admins":                                    "auth and security configuration",
		"/etc/login.defs":                                          "auth and security configuration",
		"/etc/default/useradd":                                     "auth and security configuration",
		"/etc/adduser.conf":                                        "auth and security configuration",
		"/etc/locale.conf":                                         "localization configuration",
		"/etc/timezone":                                            "localization configuration",
		"/etc/ssh/sshd_config":                                     "ssh daemon configuration",
		"/etc/ssh/ssh_config":                                      "ssh client configuration",
		"/etc/sysctl.conf":                                         "kernel or device tuning",
		"/etc/nftables.conf":                                       "firewall configuration",
		"/etc/ufw/ufw.conf":                                        "firewall configuration",
		"/etc/default/ufw":                                         "firewall configuration",
		"/etc/netplan":                                             "network configuration",
		"/etc/NetworkManager/NetworkManager.conf":                  "network configuration",
		"/etc/resolv.conf":                                         "network configuration",
		"/etc/systemd/resolved.conf":                               "network configuration",
		"/etc/sysctl.d/99-local.conf":                              "kernel or device tuning",
		"/etc/modprobe.d/local.conf":                               "kernel or device tuning",
		"/etc/udev/rules.d/99-device.rules":                        "kernel or device tuning",
		"/etc/pam.d/sshd":                                          "auth and security configuration",
		"/etc/security/limits.d/audio.conf":                        "auth and security configuration",
		"/etc/polkit-1/rules.d/49-admin.rules":                     "auth and security configuration",
		"/usr/local/share/polkit-1/rules.d/50-wheel.rules":         "auth and security configuration",
		"/etc/fail2ban/jail.local":                                 "auth and security configuration",
		"/etc/fail2ban/jail.d/nginx.conf":                          "auth and security configuration",
		"/etc/audit/auditd.conf":                                   "auth and security configuration",
		"/etc/audit/rules.d/hardening.rules":                       "auth and security configuration",
		"/etc/apparmor.d/usr.bin.demo":                             "auth and security configuration",
		"/etc/apparmor.d/local/usr.bin.demo":                       "auth and security configuration",
		"/etc/wireguard/wg0.conf":                                  "network configuration",
		"/etc/openvpn/client.conf":                                 "network configuration",
		"/etc/logrotate.d/app":                                     "log rotation configuration",
		"/etc/netplan/01-net.yaml":                                 "network configuration",
		"/etc/nginx/sites-enabled/app":                             "web server configuration",
		"/etc/apache2/sites-enabled/app.conf":                      "web server configuration",
		"/etc/NetworkManager/system-connections/home.nmconnection": "network connection profile may contain credentials",
	} {
		item, ok := seen[path]
		if !ok {
			t.Fatalf("missing %s in %+v", path, report.Items)
		}
		if item.Kind != "os-config" || item.Reason != reason {
			t.Fatalf("item %s=%+v, want os-config reason %q", path, item, reason)
		}
	}
	if seen["/etc/NetworkManager/system-connections/home.nmconnection"].Decision != model.DecisionMigrationNote {
		t.Fatalf("network secret should be migration note in %+v", report.Items)
	}
	if seen["/etc/ssh/sshd_config"].Details["Port"] != "2222" || seen["/etc/ssh/sshd_config"].Details["PasswordAuthentication"] != "no" {
		t.Fatalf("sshd details missing: %+v", seen["/etc/ssh/sshd_config"])
	}
	if seen["/etc/ssh/ssh_config"].Details["hosts"] != "1" || !strings.Contains(seen["/etc/ssh/ssh_config"].Details["markers"], "proxyjump") {
		t.Fatalf("ssh client details missing: %+v", seen["/etc/ssh/ssh_config"])
	}
	if seen["/etc/wireguard/wg0.conf"].Details["peers"] != "1" || seen["/etc/wireguard/wg0.conf"].Details["secret-refs"] != "2" || seen["/etc/wireguard/wg0.conf"].Details["dns"] != "present" {
		t.Fatalf("wireguard details missing or unsafe: %+v", seen["/etc/wireguard/wg0.conf"])
	}
	if seen["/etc/openvpn/client.conf"].Details["remotes"] != "1" || seen["/etc/openvpn/client.conf"].Details["routes"] != "1" || seen["/etc/openvpn/client.conf"].Details["secret-refs"] != "1" {
		t.Fatalf("openvpn details missing: %+v", seen["/etc/openvpn/client.conf"])
	}
	if seen["/etc/resolv.conf"].Details["nameservers"] != "1.1.1.1" || seen["/etc/resolv.conf"].Details["search"] != "lan example.test" {
		t.Fatalf("resolv details missing: %+v", seen["/etc/resolv.conf"])
	}
	if seen["/etc/netplan/01-net.yaml"].Details["renderer"] != "NetworkManager" || seen["/etc/netplan/01-net.yaml"].Details["dhcp4"] != "true" || seen["/etc/netplan/01-net.yaml"].Details["nameservers"] != "present" {
		t.Fatalf("netplan details missing: %+v", seen["/etc/netplan/01-net.yaml"])
	}
	nm := seen["/etc/NetworkManager/system-connections/home.nmconnection"]
	if nm.Details["id"] != "home" || nm.Details["type"] != "wifi" || nm.Details["interface-name"] != "wlp1s0" || nm.Details["psk"] != "" {
		t.Fatalf("network manager details unsafe or missing: %+v", nm)
	}
	if seen["/etc/ufw/ufw.conf"].Details["ENABLED"] != "yes" || seen["/etc/default/ufw"].Details["DEFAULT_INPUT_POLICY"] != "DROP" {
		t.Fatalf("ufw details missing: %+v %+v", seen["/etc/ufw/ufw.conf"], seen["/etc/default/ufw"])
	}
	if seen["/etc/nftables.conf"].Details["tables"] != "1" || seen["/etc/nftables.conf"].Details["chains"] != "1" || seen["/etc/nftables.conf"].Details["rules"] != "1" {
		t.Fatalf("nftables details missing: %+v", seen["/etc/nftables.conf"])
	}
	if seen["/etc/sudoers"].Details["user-rules"] != "1" || seen["/etc/sudoers"].Details["group-rules"] != "1" || seen["/etc/sudoers"].Details["nopasswd-rules"] != "1" || seen["/etc/sudoers"].Details["includes"] != "1" {
		t.Fatalf("sudoers details missing: %+v", seen["/etc/sudoers"])
	}
	if seen["/etc/login.defs"].Details["UID_MIN"] != "1000" || seen["/etc/login.defs"].Details["PASS_MAX_DAYS"] != "90" || seen["/etc/login.defs"].Details["UMASK"] != "027" {
		t.Fatalf("login.defs details missing: %+v", seen["/etc/login.defs"])
	}
	if seen["/etc/default/useradd"].Details["SHELL"] != "/bin/bash" || seen["/etc/adduser.conf"].Details["DSHELL"] != "/bin/zsh" {
		t.Fatalf("useradd/adduser details missing: %+v %+v", seen["/etc/default/useradd"], seen["/etc/adduser.conf"])
	}
	if seen["/etc/pam.d/sshd"].Details["rules"] != "3" || !strings.Contains(seen["/etc/pam.d/sshd"].Details["important-modules"], "pam_faillock.so") || strings.Contains(seen["/etc/pam.d/sshd"].Details["modules"], "hidden") {
		t.Fatalf("pam details unsafe or missing: %+v", seen["/etc/pam.d/sshd"])
	}
	if seen["/etc/security/limits.d/audio.conf"].Details["entries"] != "1" || seen["/etc/security/limits.d/audio.conf"].Details["domains"] != "@audio" {
		t.Fatalf("security conf details missing: %+v", seen["/etc/security/limits.d/audio.conf"])
	}
	if seen["/etc/polkit-1/rules.d/49-admin.rules"].Details["admin-rules"] != "1" || seen["/etc/polkit-1/rules.d/49-admin.rules"].Details["mentions-sudo"] != "true" {
		t.Fatalf("polkit details missing: %+v", seen["/etc/polkit-1/rules.d/49-admin.rules"])
	}
	if seen["/etc/fail2ban/jail.local"].Details["enabled-jails"] != "1" || seen["/etc/fail2ban/jail.local"].Details["maxretry"] != "5" {
		t.Fatalf("fail2ban details missing: %+v", seen["/etc/fail2ban/jail.local"])
	}
	if seen["/etc/audit/rules.d/hardening.rules"].Details["rules"] != "2" || seen["/etc/audit/rules.d/hardening.rules"].Details["watches"] != "1" || seen["/etc/audit/rules.d/hardening.rules"].Details["syscall-rules"] != "1" {
		t.Fatalf("audit rules details missing: %+v", seen["/etc/audit/rules.d/hardening.rules"])
	}
	if seen["/etc/apparmor.d/usr.bin.demo"].Details["profiles"] != "1" || seen["/etc/apparmor.d/usr.bin.demo"].Details["includes"] != "1" || seen["/etc/apparmor.d/usr.bin.demo"].Details["capabilities"] != "1" {
		t.Fatalf("apparmor details missing: %+v", seen["/etc/apparmor.d/usr.bin.demo"])
	}
	services := map[string]model.Service{}
	for _, service := range report.Services {
		services[service.Path] = service
	}
	for path, manager := range map[string]string{
		"/etc/systemd/system/custom.service":            "systemd",
		"/etc/systemd/system/custom.timer":              "systemd",
		"/home/alice/.config/systemd/user/user.service": "systemd",
		"/etc/cron.d/job":                               "cron",
		"/var/spool/cron/crontabs/alice":                "cron",
	} {
		if services[path].Manager != manager {
			t.Fatalf("service %s manager=%q, want %q in %+v", path, services[path].Manager, manager, report.Services)
		}
	}
	custom := services["/etc/systemd/system/custom.service"]
	if custom.Description != "Custom app" || custom.User != "app" || custom.WorkingDirectory != "/srv/app" || custom.ExecStart != "/opt/vendor/bin/app --token=super-secret" {
		t.Fatalf("custom systemd details missing: %+v", custom)
	}
	if len(custom.EnvironmentFiles) != 1 || custom.EnvironmentFiles[0] != "/etc/default/custom" || len(custom.WantedBy) != 1 || custom.WantedBy[0] != "multi-user.target" {
		t.Fatalf("custom systemd lists missing: %+v", custom)
	}
	if services["/etc/systemd/system/custom.timer"].Schedule != "OnCalendar=daily" {
		t.Fatalf("timer schedule missing: %+v", services["/etc/systemd/system/custom.timer"])
	}
	if services["/home/alice/.config/systemd/user/user.service"].Description != "User app" || services["/home/alice/.config/systemd/user/user.service"].ExecStart != "/home/alice/bin/app" {
		t.Fatalf("user systemd details missing: %+v", services["/home/alice/.config/systemd/user/user.service"])
	}
	if services["/etc/cron.d/job"].Schedule != "15 2 * * *" || services["/etc/cron.d/job"].User != "root" || services["/etc/cron.d/job"].ExecStart != "/usr/local/bin/job" {
		t.Fatalf("cron.d details missing: %+v", services["/etc/cron.d/job"])
	}
	if services["/var/spool/cron/crontabs/alice"].Schedule != "*/5 * * * *" || services["/var/spool/cron/crontabs/alice"].User != "alice" || services["/var/spool/cron/crontabs/alice"].ExecStart != "/home/alice/bin/task" {
		t.Fatalf("spool cron details missing: %+v", services["/var/spool/cron/crontabs/alice"])
	}
}

func TestUserConfigScannerFindsShellAndUserConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.bashrc", "alias ll='ls -la'\n")
	write(t, root, "/home/alice/.bash_profile", ". ~/.bashrc\n")
	write(t, root, "/home/alice/.profile", "export PATH=$HOME/.local/bin:$PATH\n")
	write(t, root, "/home/alice/.zshrc", "source ~/.zinit/bin/zinit.zsh\n")
	write(t, root, "/home/alice/.zprofile", "export EDITOR=nvim\n")
	write(t, root, "/home/alice/.config/fish/config.fish", "set -gx EDITOR nvim\n")
	write(t, root, "/home/alice/.config/fish/functions/f.fish", "function f\nend\n")
	write(t, root, "/home/alice/.config/fish/conf.d/path.fish", "fish_add_path ~/.local/bin\n")
	write(t, root, "/home/alice/.oh-my-zsh/.keep", "")
	write(t, root, "/home/alice/.zinit/.keep", "")
	write(t, root, "/home/alice/.antigen/.keep", "")
	writeMode(t, root, "/home/alice/.local/bin/tool", []byte("#!/bin/sh\n"), 0o755)
	write(t, root, "/home/alice/.pam_environment", "EDITOR=nvim\n")
	write(t, root, "/home/alice/.config/environment.d/editor.conf", "EDITOR=nvim\n")
	write(t, root, "/home/alice/.direnvrc", "layout_python\n")
	write(t, root, "/home/alice/project/.envrc", "use flake\n")
	write(t, root, "/home/alice/.gitconfig", "[user]\nname = Alice\n")
	write(t, root, "/home/alice/.gitignore_global", "*.swp\n")
	write(t, root, "/home/alice/.ssh/config", "Host example\n  HostName example.com\n  IdentityFile ~/.ssh/id_ed25519\n  ProxyJump bastion\n")
	write(t, root, "/home/alice/.ssh/authorized_keys", "command=\"/usr/local/bin/check\" ssh-ed25519 AAAA demo\nssh-rsa BBBB legacy\n")
	write(t, root, "/home/alice/.ssh/known_hosts", "|1|hash|salt ssh-ed25519 AAAA\nexample.com ssh-rsa BBBB\n")
	write(t, root, "/home/alice/.gnupg/gpg.conf", "use-agent\n")
	write(t, root, "/home/alice/.password-store/.keep", "")
	write(t, root, "/home/alice/.local/share/keyrings/login.keyring", "raw-secret")
	write(t, root, "/home/alice/.tmux.conf", "set -g mouse on\n")
	write(t, root, "/home/alice/.config/starship.toml", "[character]\n")

	report := &model.ScanReport{}
	if err := (UserConfigScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, item := range report.Items {
		seen[item.Path] = item.Kind
		if item.Kind != "credential-store" && item.Decision != model.DecisionCandidate {
			t.Fatalf("user config decision=%q, want candidate", item.Decision)
		}
	}
	for path, kind := range map[string]string{
		"/home/alice/.bashrc":                           "shell-config",
		"/home/alice/.bash_profile":                     "shell-config",
		"/home/alice/.profile":                          "shell-config",
		"/home/alice/.zshrc":                            "shell-config",
		"/home/alice/.zprofile":                         "shell-config",
		"/home/alice/.config/fish/config.fish":          "shell-config",
		"/home/alice/.config/fish/functions/f.fish":     "shell-config",
		"/home/alice/.config/fish/conf.d/path.fish":     "shell-config",
		"/home/alice/.oh-my-zsh":                        "shell-plugin",
		"/home/alice/.zinit":                            "shell-plugin",
		"/home/alice/.antigen":                          "shell-plugin",
		"/home/alice/.local/bin/tool":                   "user-bin",
		"/home/alice/.pam_environment":                  "shell-config",
		"/home/alice/.config/environment.d/editor.conf": "shell-config",
		"/home/alice/.direnvrc":                         "shell-config",
		"/home/alice/project/.envrc":                    "direnv",
		"/home/alice/.gitconfig":                        "user-config",
		"/home/alice/.gitignore_global":                 "user-config",
		"/home/alice/.ssh/config":                       "user-config",
		"/home/alice/.ssh/authorized_keys":              "user-config",
		"/home/alice/.ssh/known_hosts":                  "user-config",
		"/home/alice/.gnupg/gpg.conf":                   "user-config",
		"/home/alice/.password-store":                   "credential-store",
		"/home/alice/.local/share/keyrings":             "credential-store",
		"/home/alice/.tmux.conf":                        "user-config",
		"/home/alice/.config/starship.toml":             "user-config",
	} {
		if seen[path] != kind {
			t.Fatalf("path %s kind=%q, want %q in %+v", path, seen[path], kind, report.Items)
		}
	}
	details := map[string]model.Item{}
	for _, item := range report.Items {
		details[item.Path] = item
	}
	if details["/home/alice/.ssh/config"].Details["hosts"] != "1" || details["/home/alice/.ssh/config"].Details["identity-files"] != "1" || !strings.Contains(details["/home/alice/.ssh/config"].Details["markers"], "proxyjump") {
		t.Fatalf("ssh config details missing: %+v", details["/home/alice/.ssh/config"])
	}
	if details["/home/alice/.ssh/authorized_keys"].Details["keys"] != "2" || details["/home/alice/.ssh/authorized_keys"].Details["restricted-keys"] != "1" || !strings.Contains(details["/home/alice/.ssh/authorized_keys"].Details["key-types"], "ssh-ed25519") {
		t.Fatalf("authorized_keys details missing: %+v", details["/home/alice/.ssh/authorized_keys"])
	}
	if details["/home/alice/.ssh/known_hosts"].Details["entries"] != "2" || details["/home/alice/.ssh/known_hosts"].Details["hashed-hosts"] != "1" {
		t.Fatalf("known_hosts details missing: %+v", details["/home/alice/.ssh/known_hosts"])
	}
	if details["/home/alice/.password-store"].Decision != model.DecisionMigrationNote || details["/home/alice/.local/share/keyrings"].Details["store"] != "keyrings" {
		t.Fatalf("credential store details missing: %+v %+v", details["/home/alice/.password-store"], details["/home/alice/.local/share/keyrings"])
	}
}

func TestDesktopScannerFindsMarkersAssetsAndConfigs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/share/gnome/.keep", "")
	write(t, root, "/home/alice/.local/share/fonts/demo.ttf", "font")
	write(t, root, "/home/alice/.themes/demo/index.theme", "[Theme]\n")
	write(t, root, "/home/alice/.config/autostart/tool.desktop", "[Desktop Entry]\n")
	write(t, root, "/home/alice/.config/kdeglobals", "[KDE]\n")
	write(t, root, "/home/alice/.config/kwinrc", "[KWin]\n")
	write(t, root, "/home/alice/.config/i3/config", "bindsym Mod4+Enter exec alacritty\n")
	write(t, root, "/home/alice/.config/sway/config", "set $mod Mod4\n")
	write(t, root, "/home/alice/.config/fcitx5/profile", "[Groups]\n")
	write(t, root, "/home/alice/.config/ibus/bus", "")
	write(t, root, "/home/alice/.config/alacritty/alacritty.toml", "[window]\n")
	write(t, root, "/home/alice/.config/kitty/kitty.conf", "font_size 12\n")
	write(t, root, "/home/alice/.config/Code/User/settings.json", "{}")
	write(t, root, "/home/alice/.config/Code/User/snippets/go.json", "{}")
	write(t, root, "/home/alice/.vscode/extensions/publisher.tool-1.0.0/.keep", "")
	write(t, root, "/home/alice/.config/JetBrains/IdeaIC2026.1/options/editor.xml", "<application />")
	write(t, root, "/home/alice/.config/nvim/init.lua", "vim.opt.number = true\n")
	write(t, root, "/home/alice/.vimrc", "set number\n")
	write(t, root, "/home/alice/.mozilla/firefox/profiles.ini", "[Profile0]\n")
	write(t, root, "/home/alice/.mozilla/firefox/alice.default-release/cookies.sqlite", "raw-cookie-secret")
	write(t, root, "/home/alice/.mozilla/firefox/alice.default-release/extensions/addon@example.xpi", "xpi")
	write(t, root, "/home/alice/.config/google-chrome/Default/History", "raw-history")
	write(t, root, "/home/alice/.config/google-chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0/manifest.json", "{}")

	report := &model.ScanReport{}
	if err := (DesktopScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	if report.Desktop.Environment != "gnome" {
		t.Fatalf("environment=%q, want gnome", report.Desktop.Environment)
	}
	if len(report.Desktop.Fonts) != 1 || report.Desktop.Fonts[0] != "/home/alice/.local/share/fonts/demo.ttf" {
		t.Fatalf("unexpected fonts: %+v", report.Desktop.Fonts)
	}
	if len(report.Desktop.Themes) != 1 || report.Desktop.Themes[0] != "/home/alice/.themes/demo" {
		t.Fatalf("unexpected themes: %+v", report.Desktop.Themes)
	}
	if len(report.Desktop.Autostart) != 1 || report.Desktop.Autostart[0].Path != "/home/alice/.config/autostart/tool.desktop" {
		t.Fatalf("unexpected autostart: %+v", report.Desktop.Autostart)
	}
	seen := map[string]bool{}
	for _, item := range report.Items {
		if item.Kind == "desktop-config" {
			seen[item.Path] = true
			if item.Decision != model.DecisionCandidate {
				t.Fatalf("desktop config decision=%q, want candidate", item.Decision)
			}
		}
	}
	for _, want := range []string{
		"/home/alice/.config/kdeglobals",
		"/home/alice/.config/kwinrc",
		"/home/alice/.config/i3/config",
		"/home/alice/.config/sway/config",
		"/home/alice/.config/fcitx5/profile",
		"/home/alice/.config/ibus/bus",
		"/home/alice/.config/alacritty/alacritty.toml",
		"/home/alice/.config/kitty/kitty.conf",
		"/home/alice/.config/Code/User/settings.json",
		"/home/alice/.config/nvim/init.lua",
		"/home/alice/.vimrc",
	} {
		if !seen[want] {
			t.Fatalf("missing desktop config %q in %+v", want, report.Items)
		}
	}
	items := map[string]model.Item{}
	for _, item := range report.Items {
		items[item.Path] = item
	}
	for _, path := range []string{
		"/home/alice/.mozilla/firefox/profiles.ini",
		"/home/alice/.mozilla/firefox/alice.default-release",
		"/home/alice/.config/google-chrome/Default",
	} {
		if items[path].Kind != "browser-profile" || items[path].Decision != model.DecisionMigrationNote {
			t.Fatalf("browser profile %s missing migration note in %+v", path, report.Items)
		}
	}
	for _, path := range []string{
		"/home/alice/.mozilla/firefox/alice.default-release/extensions/addon@example.xpi",
		"/home/alice/.config/google-chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if items[path].Kind != "browser-extension" || items[path].Decision != model.DecisionMigrationNote {
			t.Fatalf("browser extension %s missing migration note in %+v", path, report.Items)
		}
	}
	for _, path := range []string{
		"/home/alice/.config/Code/User/settings.json",
		"/home/alice/.config/Code/User/snippets",
		"/home/alice/.vscode/extensions/publisher.tool-1.0.0",
		"/home/alice/.config/JetBrains/IdeaIC2026.1",
	} {
		if items[path].Kind != "editor-profile" || items[path].Decision != model.DecisionCandidate {
			t.Fatalf("editor profile %s missing candidate in %+v", path, report.Items)
		}
	}
	for _, item := range report.Items {
		if strings.Contains(item.Reason, "raw-cookie-secret") || strings.Contains(item.Reason, "raw-history") {
			t.Fatalf("desktop scanner leaked raw profile content: %+v", item)
		}
	}
}

func TestDesktopScannerDconfUsesRunnerOnHostRoot(t *testing.T) {
	report := &model.ScanReport{}
	called := false
	err := (DesktopScanner{}).Scan(context.Background(), Options{
		Root: "/",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			if name != "dconf" || strings.Join(args, " ") != "dump /" {
				t.Fatalf("unexpected command: %s %v", name, args)
			}
			return []byte("[org/gnome/desktop/interface]\ncolor-scheme='prefer-dark'\n"), nil
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected dconf runner to be called")
	}
	if len(report.Desktop.Dconf) != 2 || report.Desktop.Dconf[1] != "color-scheme='prefer-dark'" {
		t.Fatalf("unexpected dconf dump: %+v", report.Desktop.Dconf)
	}
}

func TestDesktopScannerDoesNotRunDconfForMountedRoot(t *testing.T) {
	root := t.TempDir()
	report := &model.ScanReport{}
	called := false
	err := (DesktopScanner{}).Scan(context.Background(), Options{
		Root: root,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return nil, errors.New("should not run")
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("dconf runner should not be called for mounted root")
	}
}

func TestContainerScannerUsesInspectForRuntimeDetails(t *testing.T) {
	report := &model.ScanReport{}
	err := (ContainerScanner{}).Scan(context.Background(), Options{
		Root: "/",
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			switch command {
			case `docker ps -a --format {{json .}}`:
				return []byte(`{"Names":"web","Image":"nginx:1.27","Ports":"0.0.0.0:8080->80/tcp"}` + "\n"), nil
			case "docker inspect web":
				return []byte(`[{
					"Config":{"Image":"nginx:1.27","Env":["TOKEN=secret","MODE=prod"]},
					"RepoDigests":["nginx@sha256:demo"],
					"Mounts":[{"Type":"bind","Source":"/srv/web","Destination":"/app"}]
				}]`), nil
			case `podman ps -a --format {{json .}}`:
				return []byte(`{"Names":"db","Image":"postgres:16","Ports":""}` + "\n"), nil
			case "podman inspect db":
				return []byte(`[{
					"Config":{"Image":"postgres:16","Env":["POSTGRES_PASSWORD=secret"]},
					"RepoDigests":["postgres@sha256:demo"],
					"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIP":"127.0.0.1","HostPort":"5432"}]}},
					"Mounts":[{"Type":"volume","Source":"pgdata","Destination":"/var/lib/postgresql/data"}]
				}]`), nil
			default:
				return nil, errors.New("unexpected command: " + command)
			}
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Container{}
	for _, container := range report.Containers {
		seen[container.Runtime+":"+container.Name] = container
	}
	web := seen["docker:web"]
	if web.Image != "nginx:1.27" || web.Digest != "nginx@sha256:demo" || len(web.Mounts) != 1 || web.Mounts[0] != "bind:/srv/web:/app" {
		t.Fatalf("unexpected docker container: %+v", web)
	}
	if _, ok := web.Env["TOKEN"]; !ok {
		t.Fatalf("docker env keys missing TOKEN: %+v", web.Env)
	}
	if web.Env["TOKEN"] != "" {
		t.Fatalf("docker env value should be redacted: %+v", web.Env)
	}
	db := seen["podman:db"]
	if db.Image != "postgres:16" || db.Digest != "postgres@sha256:demo" || len(db.Ports) != 1 || db.Ports[0] != "127.0.0.1:5432->5432/tcp" {
		t.Fatalf("unexpected podman container: %+v", db)
	}
	if _, ok := db.Env["POSTGRES_PASSWORD"]; !ok || db.Env["POSTGRES_PASSWORD"] != "" {
		t.Fatalf("podman env key should be present with redacted value: %+v", db.Env)
	}
}

func TestContainerScannerMountedRootFindsComposeWithoutRuntimeCommands(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/app/compose.yaml", "services: {}\n")
	write(t, root, "/home/alice/app/compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/docker-compose.yml", "services: {}\n")
	write(t, root, "/home/alice/app/docker-compose.yaml", "services: {}\n")
	write(t, root, "/srv/app/docker-compose.yaml", "services: {}\n")

	report := &model.ScanReport{}
	called := false
	err := (ContainerScanner{}).Scan(context.Background(), Options{
		Root: root,
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			called = true
			return nil, errors.New("runtime command should not run")
		},
	}, report)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("runtime command should not be called for mounted root")
	}
	seen := map[string]bool{}
	for _, container := range report.Containers {
		seen[container.Compose] = true
	}
	for _, want := range []string{
		"/home/alice/app/compose.yaml",
		"/home/alice/app/compose.yml",
		"/home/alice/app/docker-compose.yml",
		"/home/alice/app/docker-compose.yaml",
		"/srv/app/docker-compose.yaml",
	} {
		if !seen[want] {
			t.Fatalf("missing compose %s in %+v", want, report.Containers)
		}
	}
}

func TestPackageEcosystemScannerFindsFlatpakAppImageAndHomebrew(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/flatpak/app/org.example.App/current/active/files/bin/app", "")
	write(t, root, "/var/lib/flatpak/app/org.example.App/current/active/metadata", "[Application]\nruntime=org.gnome.Platform/x86_64/46\nsdk=org.gnome.Sdk/x86_64/46\ncommand=secret-command\n")
	write(t, root, "/snap/hello", "snap")
	writeMode(t, root, "/home/alice/Applications/Tool-1.2.3.AppImage", []byte("appimage"), 0o755)
	write(t, root, "/home/alice/Applications/Tool-1.2.3.desktop", "[Desktop Entry]\nExec=/home/alice/Applications/Tool-1.2.3.AppImage --token secret-value\n")
	write(t, root, "/home/linuxbrew/.linuxbrew/Cellar/hello/1.0/INSTALL_RECEIPT.json", `{"source":{"tap":"homebrew/core"},"runtime_dependencies":[{},{}],"installed_on_request":true}`)

	report := &model.ScanReport{}
	if err := (PackageEcosystemScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Package{}
	for _, pkg := range report.Packages {
		seen[pkg.Manager+":"+pkg.Name] = pkg
		if pkg.Manager == "appimage" && len(pkg.NixNames) != 0 {
			t.Fatalf("appimage should not get nix mapping: %+v", pkg)
		}
	}
	for _, want := range []string{"snap:hello", "flatpak:org.example.App", "appimage:Tool-1.2.3", "homebrew:hello"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("missing %s in %+v", want, report.Packages)
		}
	}
	if seen["snap:hello"].Details["mount"] != "present" || seen["snap:hello"].Details["source-kind"] != "snap-file" {
		t.Fatalf("snap details missing: %+v", seen["snap:hello"])
	}
	flatpak := seen["flatpak:org.example.App"]
	if flatpak.Details["scope"] != "system" || flatpak.Details["current"] != "present" || flatpak.Details["runtime"] != "org.gnome.Platform" || flatpak.Details["sdk"] != "present" || flatpak.Details["command"] != "present" {
		t.Fatalf("flatpak details missing: %+v", flatpak)
	}
	appimage := seen["appimage:Tool-1.2.3"]
	if appimage.Details["location"] != "user-applications" || appimage.Details["executable"] != "present" || appimage.Details["filename-version"] != "1.2.3" || appimage.Details["desktop-entry"] != "present" {
		t.Fatalf("appimage details missing: %+v", appimage)
	}
	brew := seen["homebrew:hello"]
	if brew.Details["prefix"] != "/home/linuxbrew/.linuxbrew" || brew.Details["version-count"] != "1" || brew.Details["current-version"] != "1.0" || brew.Details["tap"] != "present" || brew.Details["dependency-count"] != "2" || brew.Details["installed-on-request"] != "true" {
		t.Fatalf("homebrew details missing: %+v", brew)
	}
	for _, pkg := range report.Packages {
		for _, value := range pkg.Details {
			for _, leaked := range []string{"secret-value", "secret-command", "homebrew/core"} {
				if strings.Contains(value, leaked) {
					t.Fatalf("package details leaked %q in %+v", leaked, pkg)
				}
			}
		}
	}
}

func TestLanguageScannerAddsNixCandidatesForKnownCLIs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/usr/local/lib/node_modules/typescript/package.json", `{"name":"typescript","version":"5.0.0"}`)
	write(t, root, "/usr/local/lib/node_modules/vite/package.json", `{"name":"vite","version":"6.0.0"}`)
	write(t, root, "/home/alice/.local/pipx/venvs/ruff/pipx_metadata.json", `{}`)
	writeMode(t, root, "/home/alice/.cargo/bin/starship", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/.cargo/bin/git-delta", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/go/bin/gopls", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/go/bin/buf", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/.gem/ruby/3.3.0/bin/bundler", []byte("#!/bin/sh\n"), 0o755)
	writeMode(t, root, "/home/alice/.gem/ruby/3.3.0/bin/rubocop", []byte("#!/bin/sh\n"), 0o755)

	report := &model.ScanReport{}
	if err := (LanguageScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	assertPkgMapping(t, report.Languages.NPM, "typescript", "nodePackages.typescript")
	assertPkgMapping(t, report.Languages.NPM, "vite", "nodePackages.vite")
	if len(report.Languages.Python) != 1 {
		t.Fatalf("python envs=%d, want 1", len(report.Languages.Python))
	}
	assertPkgMapping(t, report.Languages.Python[0].Packages, "ruff", "ruff")
	assertPkgMapping(t, report.Languages.Cargo, "starship", "starship")
	assertPkgMapping(t, report.Languages.Cargo, "git-delta", "delta")
	assertPkgMapping(t, report.Languages.Go, "gopls", "gopls")
	assertPkgMapping(t, report.Languages.Go, "buf", "buf")
	assertPkgMapping(t, report.Languages.Gem, "bundler", "bundler")
	assertPkgMapping(t, report.Languages.Gem, "rubocop", "rubocop")
}

func TestLanguageScannerFindsLanguageEcosystemHints(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/home/alice/.local/share/pnpm/global/5/node_modules/prettier/package.json", `{"name":"prettier","version":"3.0.0"}`)
	write(t, root, "/home/alice/.config/yarn/global/node_modules/yarn/package.json", `{"name":"yarn","version":"1.22.0"}`)
	write(t, root, "/home/alice/project/package.json", `{"packageManager":"pnpm@9.0.0"}`)
	write(t, root, "/home/alice/project/pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
	write(t, root, "/home/alice/project/pyproject.toml", "[project]\nname='demo'\n")
	write(t, root, "/home/alice/project/requirements.txt", "ruff\n")
	write(t, root, "/home/alice/project/poetry.lock", "# lock\n")
	write(t, root, "/home/alice/project/Pipfile", "[packages]\n")
	write(t, root, "/home/alice/project/uv.lock", "version = 1\n")
	write(t, root, "/home/alice/project/environment.yml", "name: demo\n")
	write(t, root, "/home/alice/project/Cargo.toml", "[package]\n")
	write(t, root, "/home/alice/project/go.mod", "module example.com/demo\n")
	write(t, root, "/home/alice/project/Gemfile", "source 'https://rubygems.org'\n")
	write(t, root, "/srv/app/Gemfile", "source 'https://rubygems.org'\n")
	write(t, root, "/home/alice/miniconda3/envs/data/conda-meta/history", "")
	write(t, root, "/home/alice/.condarc", "channels:\n")
	write(t, root, "/home/alice/.tool-versions", "nodejs 22\n")
	write(t, root, "/home/alice/project/.node-version", "22\n")
	write(t, root, "/home/alice/.local/share/mise/config.toml", "")

	report := &model.ScanReport{}
	if err := (LanguageScanner{}).Scan(context.Background(), Options{Root: root}, report); err != nil {
		t.Fatal(err)
	}

	assertPkgMapping(t, report.Languages.NPM, "prettier", "nodePackages.prettier")
	assertPkgMapping(t, report.Languages.NPM, "yarn", "yarn")
	if len(report.Languages.Conda) != 1 || report.Languages.Conda[0].Name != "data" || report.Languages.Conda[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("unexpected conda envs: %+v", report.Languages.Conda)
	}
	vms := map[string]bool{}
	for _, vm := range report.Languages.VMs {
		vms[vm.Name+"@"+vm.Path] = true
	}
	for _, want := range []string{"mise@/home/alice/.local/share/mise", ".tool-versions@/home/alice/.tool-versions", ".node-version@/home/alice/project/.node-version"} {
		if !vms[want] {
			t.Fatalf("missing version manager marker %s in %+v", want, report.Languages.VMs)
		}
	}
	items := map[string]model.Item{}
	for _, item := range report.Items {
		if item.Kind == "language-project" {
			items[item.Path] = item
		}
	}
	for _, path := range []string{
		"/home/alice/project/package.json",
		"/home/alice/project/pnpm-lock.yaml",
		"/home/alice/project/pyproject.toml",
		"/home/alice/project/requirements.txt",
		"/home/alice/project/poetry.lock",
		"/home/alice/project/Pipfile",
		"/home/alice/project/uv.lock",
		"/home/alice/project/environment.yml",
		"/home/alice/project/Cargo.toml",
		"/home/alice/project/go.mod",
		"/home/alice/project/Gemfile",
		"/srv/app/Gemfile",
		"/home/alice/.condarc",
	} {
		if items[path].Decision != model.DecisionCandidate {
			t.Fatalf("missing language project item %s in %+v", path, report.Items)
		}
	}
}

func assertPkgMapping(t *testing.T, packages []model.Package, name, want string) {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name {
			if len(pkg.NixNames) != 1 || pkg.NixNames[0] != want {
				t.Fatalf("%s nixNames=%v, want [%s]", name, pkg.NixNames, want)
			}
			return
		}
	}
	t.Fatalf("package %s missing from %+v", name, packages)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func write(t *testing.T, root, path, content string) {
	t.Helper()
	writeMode(t, root, path, []byte(content), 0o644)
}

func writeMode(t *testing.T, root, path string, content []byte, mode os.FileMode) {
	t.Helper()
	abs := filepath.Join(root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, content, mode); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
