package doctor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	Boot    bool
	Host    string
	Timeout time.Duration
	Runner  Runner
}

type Runner func(context.Context, string, ...string) ([]byte, error)

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
		"modules/services.nix",
		"modules/filesystem-findings.nix",
		"reports/package-sources.md",
		"reports/filesystem.md",
		"reports/users.md",
		"reports/containers.md",
		"reports/git-sources.md",
		"reports/languages.md",
		"reports/dev-projects.md",
		"reports/user-config.md",
		"reports/desktop.md",
		"reports/migration-report.md",
		"reports/migration-checklist.md",
		"reports/system-config.md",
		"reports/devops-config.md",
		"reports/backup-sync.md",
		"reports/hardware.md",
	}
	var checks []Check
	for _, rel := range required {
		_, err := os.Stat(filepath.Join(project, rel))
		checks = append(checks, Check{Name: "file:" + rel, OK: err == nil, Message: errorMessage(err)})
	}
	return checks
}

func Run(ctx context.Context, opts Options) Result {
	if opts.Boot {
		opts.VM = true
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	runner := opts.Runner
	if runner == nil {
		runner = defaultRunner
	}
	result := Result{Project: opts.Project, OK: true}
	result.Checks = append(result.Checks, CheckProjectFiles(opts.Project)...)
	for _, c := range result.Checks {
		if !c.OK {
			result.OK = false
		}
	}
	if opts.Runner == nil {
		if _, err := exec.LookPath("nix"); err != nil {
			result.Checks = append(result.Checks, Check{Name: "nix", OK: false, Message: "nix command not found; skipping flake validation"})
			result.Suggestions = append(result.Suggestions, "Install Nix to run nix flake check and VM validation.")
			result.OK = false
			return result
		}
	}
	if out, err := runner(ctx, "nix", "flake", "check", opts.Project); err != nil {
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
			if out, err := runner(ctx, "nix", "build", attr); err != nil {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: false, Message: string(out)})
				result.OK = false
			} else {
				result.Checks = append(result.Checks, Check{Name: "vm build:" + host, OK: true})
				script := vmScriptPath(host)
				if _, err := os.Stat(script); err != nil {
					result.Checks = append(result.Checks, Check{Name: "vm script:" + host, OK: false, Message: err.Error()})
					result.OK = false
				} else {
					result.Checks = append(result.Checks, Check{Name: "vm script:" + host, OK: true, Message: script})
					if opts.Boot {
						bootCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
						out, err := runner(bootCtx, script)
						cancel()
						if err != nil {
							if bootCtx.Err() == context.DeadlineExceeded {
								result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: true, Message: "VM process started and reached timeout without immediate failure"})
							} else {
								result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: false, Message: string(out)})
								result.OK = false
							}
						} else {
							result.Checks = append(result.Checks, Check{Name: "vm boot:" + host, OK: true, Message: string(out)})
						}
					} else {
						result.Suggestions = append(result.Suggestions, "Run "+script+" to boot the generated VM after reviewing secrets and migration notes.")
					}
				}
			}
		}
	}
	return result
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func vmScriptPath(host string) string {
	return filepath.Join("result", "bin", "run-"+host+"-vm")
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
