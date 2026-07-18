package doctor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Result struct {
	Project     string   `json:"project"`
	OK          bool     `json:"ok"`
	Checks      []Check  `json:"checks"`
	Suggestions []string `json:"suggestions,omitempty"`
}

type Options struct {
	Project string
	VM      bool
	Host    string
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

func Run(ctx context.Context, opts Options) Result {
	result := Result{Project: opts.Project, OK: true}
	result.Checks = append(result.Checks, CheckProjectFiles(opts.Project)...)
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
	cmd := exec.CommandContext(ctx, "nix", "flake", "check", opts.Project)
	if out, err := cmd.CombinedOutput(); err != nil {
		result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: false, Message: string(out)})
		result.OK = false
	} else {
		result.Checks = append(result.Checks, Check{Name: "nix flake check", OK: true})
	}
	if opts.VM {
		host := opts.Host
		if host == "" {
			host = detectHost(opts.Project)
		}
		if host == "" {
			result.Checks = append(result.Checks, Check{Name: "vm", OK: false, Message: "could not detect host; pass --host"})
			result.OK = false
		} else {
			attr := opts.Project + "#nixosConfigurations." + host + ".config.system.build.vm"
			vmCmd := exec.CommandContext(ctx, "nix", "build", attr)
			if out, err := vmCmd.CombinedOutput(); err != nil {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: false, Message: string(out)})
				result.OK = false
			} else {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: true})
				result.Suggestions = append(result.Suggestions, "Run ./result/bin/run-"+host+"-vm to boot the generated VM after reviewing secrets and migration notes.")
			}
		}
	}
	return result
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func detectHost(project string) string {
	flake, err := os.ReadFile(filepath.Join(project, "flake.nix"))
	if err != nil {
		return ""
	}
	text := string(flake)
	marker := "nixosConfigurations."
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	rest := text[idx+len(marker):]
	var host []rune
	for _, r := range rest {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			host = append(host, r)
			continue
		}
		break
	}
	return string(host)
}
