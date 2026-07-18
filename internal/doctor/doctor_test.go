package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectHostFromGeneratedFlake(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "flake.nix"), []byte(`{
  outputs = { self, nixpkgs, ... }: {
    nixosConfigurations.demo-host = nixpkgs.lib.nixosSystem { };
  };
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectHost(project); got != "demo-host" {
		t.Fatalf("host=%q, want demo-host", got)
	}
}

func TestCheckProjectFilesRequiresGeneratedFiles(t *testing.T) {
	project := t.TempDir()
	checks := CheckProjectFiles(project)
	if len(checks) == 0 {
		t.Fatal("expected checks")
	}
	for _, check := range checks {
		if check.OK {
			t.Fatalf("empty project should fail required file check: %+v", check)
		}
	}
}
