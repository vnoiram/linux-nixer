package scanner

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type UserConfigScanner struct{}

func (UserConfigScanner) Name() string { return "user-config" }

func (UserConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	scanShellConfigs(opts, report)
	scanShellAssets(opts, report)
	scanUserToolConfigs(opts, report)
	return nil
}

func scanShellConfigs(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root,
		"/home/*/.bashrc",
		"/home/*/.bash_profile",
		"/home/*/.profile",
		"/home/*/.zshrc",
		"/home/*/.zprofile",
		"/home/*/.config/fish/config.fish",
		"/home/*/.pam_environment",
		"/home/*/.config/environment.d/*.conf",
		"/home/*/.direnvrc",
	) {
		addUserConfigItem(opts, report, path, "shell-config", "shell or login environment configuration")
	}
	for _, path := range recursiveGlob(opts.Root, "/home/*/**/.envrc") {
		addUserConfigItem(opts, report, path, "direnv", "direnv project environment file")
	}
}

func scanShellAssets(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root,
		"/home/*/.config/fish/functions/*.fish",
		"/home/*/.config/fish/conf.d/*.fish",
	) {
		addUserConfigItem(opts, report, path, "shell-config", "fish shell configuration")
	}
	for _, path := range glob(opts.Root,
		"/home/*/.oh-my-zsh",
		"/home/*/.zinit",
		"/home/*/.antigen",
	) {
		addUserConfigItem(opts, report, path, "shell-plugin", "shell plugin manager or plugin tree")
	}
	for _, path := range glob(opts.Root, "/home/*/.local/bin/*") {
		if isRegularExecutable(path) {
			addUserConfigItem(opts, report, path, "user-bin", "user-local executable")
		}
	}
}

func scanUserToolConfigs(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root,
		"/home/*/.gitconfig",
		"/home/*/.gitignore_global",
		"/home/*/.ssh/config",
		"/home/*/.gnupg/gpg.conf",
		"/home/*/.tmux.conf",
		"/home/*/.config/starship.toml",
	) {
		addUserConfigItem(opts, report, path, "user-config", "user tool configuration")
	}
}

func addUserConfigItem(opts Options, report *model.ScanReport, path, kind, reason string) {
	if info, err := os.Stat(path); err != nil {
		return
	} else if info.IsDir() && kind != "shell-plugin" {
		return
	}
	report.Items = append(report.Items, model.Item{
		Kind:     kind,
		Name:     userConfigName(path),
		Path:     displayPath(opts.Root, path),
		Decision: model.DecisionCandidate,
		Reason:   reason,
	})
}

func userConfigName(path string) string {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))
	if base == "config" && parent != "." && parent != string(filepath.Separator) {
		return parent + "/" + base
	}
	return base
}
