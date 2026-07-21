package scanner

import (
	"context"
	"testing"
)

func writeRepresentativeHost(t *testing.T, root string) {
	t.Helper()
	write(t, root, "/var/lib/dpkg/status", `Package: curl
Status: install ok installed
Version: 8.0

`)
	write(t, root, "/etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu noble main\n")
	write(t, root, "/etc/systemd/system/myapp.service", "[Service]\nExecStart=/opt/vendor/bin/tool\n")
	write(t, root, "/srv/app/compose.yml", "services:\n  app:\n    image: myapp:latest\n")
	write(t, root, "/home/alice/app/.git/config", "[remote \"origin\"]\n\turl = https://example.test/app.git\n")
	write(t, root, "/home/alice/app/package.json", `{"name":"app"}`)
	write(t, root, "/home/alice/.ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
	writeMode(t, root, "/opt/vendor/bin/tool", []byte("#!/bin/sh\necho tool\n"), 0o755)
	write(t, root, "/var/lib/postgresql", "postgresql data marker\n")
}

func TestDefaultRegistryScansRepresentativeHostAcrossDomains(t *testing.T) {
	root := t.TempDir()
	writeRepresentativeHost(t, root)

	report, err := DefaultRegistry().Scan(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	foundPackage := false
	for _, pkg := range report.Packages {
		if pkg.Name == "curl" {
			foundPackage = true
		}
	}
	if !foundPackage {
		t.Fatalf("expected curl package: %+v", report.Packages)
	}

	foundService := false
	for _, service := range report.Services {
		if service.Name == "myapp.service" {
			foundService = true
		}
	}
	if !foundService {
		t.Fatalf("expected myapp.service: %+v", report.Services)
	}

	foundContainer := false
	for _, container := range report.Containers {
		if container.Compose == "/srv/app/compose.yml" {
			foundContainer = true
		}
	}
	if !foundContainer {
		t.Fatalf("expected compose container: %+v", report.Containers)
	}

	foundGitSource := false
	for _, source := range report.GitSources {
		if source.Path == "/home/alice/app" {
			foundGitSource = true
		}
	}
	if !foundGitSource {
		t.Fatalf("expected git source /home/alice/app: %+v", report.GitSources)
	}

	foundProject := false
	for _, item := range report.Items {
		if item.Kind == "dev-project" && item.Path == "/home/alice/app/package.json" {
			foundProject = true
		}
	}
	if !foundProject {
		t.Fatalf("expected dev-project item for package.json: %+v", report.Items)
	}

	foundStateful := false
	for _, finding := range report.StatefulData {
		if finding.Path == "/var/lib/postgresql" {
			foundStateful = true
		}
	}
	if !foundStateful {
		t.Fatalf("expected postgresql stateful data: %+v", report.StatefulData)
	}

	sshKeyCount := 0
	foundScript := false
	for _, finding := range report.FilesystemDiff {
		if finding.Path == "/home/alice/.ssh/id_ed25519" {
			sshKeyCount++
			if finding.Category != "secret" || !finding.SecretRisk {
				t.Fatalf("expected ssh key to be flagged as secret: %+v", finding)
			}
		}
		if finding.Path == "/opt/vendor/bin/tool" {
			foundScript = true
		}
	}
	if sshKeyCount != 1 {
		t.Fatalf("expected exactly one filesystem-diff entry for ssh key, got %d: %+v", sshKeyCount, report.FilesystemDiff)
	}
	if !foundScript {
		t.Fatalf("expected /opt/vendor/bin/tool script finding: %+v", report.FilesystemDiff)
	}
}
