package doctor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

type Result struct {
	Project     string   `json:"project"`
	OK          bool     `json:"ok"`
	Checks      []Check  `json:"checks"`
	Suggestions []string `json:"suggestions,omitempty"`
}

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func CheckProjectFiles(project string) []Check {
	required := []string{
		"flake.nix",
		"hosts/generated/configuration.nix",
		"users/home.nix",
		"modules/containers.nix",
		"reports/migration-report.md",
	}
	var checks []Check
	for _, rel := range required {
		_, err := os.Stat(filepath.Join(project, rel))
		checks = append(checks, Check{Name: "file:" + rel, OK: err == nil, Message: errorMessage(err)})
	}
	return checks
}

func Run(ctx context.Context, project string, vm bool) Result {
	result := Result{Project: project, OK: true}
	result.Checks = append(result.Checks, CheckProjectFiles(project)...)
	for _, c := range result.Checks {
		if !c.OK {
			result.OK = false
		}
	}
	if _, err := exec.LookPath("nix"); err != nil {
		result.Checks = append(result.Checks, Check{Name: "nix", OK: false, Message: "nix command not found; skipping flake validation"})
		result.Suggestions = append(result.Suggestions, "Install Nix to run nix flake check and VM validation.")
		result.OK = false
		return result
	}
	cmd := exec.CommandContext(ctx, "nix", "flake", "check", project)
	if out, err := cmd.CombinedOutput(); err != nil {
		result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: false, Message: string(out)})
		result.OK = false
	} else {
		result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: true})
	}
	if vm {
		result.Checks = append(result.Checks, Check{Name: "vm", OK: false, Message: "VM boot validation is planned; use nixos-rebuild build-vm against the generated host after review"})
		result.OK = false
	}
	return result
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
