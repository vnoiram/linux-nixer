package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type DesktopScanner struct{}

func (DesktopScanner) Name() string { return "desktop" }

func (DesktopScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	scanDesktopEnvironment(opts, report)
	scanDesktopAssets(opts, report)
	scanAutostartEntries(opts, report)
	scanDesktopConfigs(opts, report)
	scanDconf(ctx, opts, report)
	return nil
}

func scanDesktopEnvironment(opts Options, report *model.ScanReport) {
	if exists(opts.Root, "/usr/bin/gnome-shell") || exists(opts.Root, "/usr/share/gnome") {
		report.Desktop.Environment = "gnome"
	}
	if exists(opts.Root, "/usr/bin/plasmashell") || exists(opts.Root, "/usr/share/plasma") {
		report.Desktop.Environment = "kde"
	}
}

func scanDesktopAssets(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root, "/usr/share/fonts/*", "/home/*/.local/share/fonts/*") {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			report.Desktop.Fonts = append(report.Desktop.Fonts, displayPath(opts.Root, path))
		}
	}
	for _, path := range glob(opts.Root, "/usr/share/themes/*", "/home/*/.themes/*", "/usr/share/icons/*", "/home/*/.icons/*") {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			report.Desktop.Themes = append(report.Desktop.Themes, displayPath(opts.Root, path))
		}
	}
}

func scanAutostartEntries(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root, "/home/*/.config/autostart/*.desktop") {
		report.Desktop.Autostart = append(report.Desktop.Autostart, model.FileFinding{
			Path:     displayPath(opts.Root, path),
			Type:     "desktop-entry",
			Category: "desktop-autostart",
			Decision: model.DecisionCandidate,
		})
	}
}

func scanDesktopConfigs(opts Options, report *model.ScanReport) {
	patterns := []string{
		"/home/*/.config/kdeglobals",
		"/home/*/.config/kwinrc",
		"/home/*/.config/kscreenlockerrc",
		"/home/*/.config/plasmarc",
		"/home/*/.config/plasma-org.kde.plasma.desktop-appletsrc",
		"/home/*/.config/i3/config",
		"/home/*/.i3/config",
		"/home/*/.config/sway/config",
		"/home/*/.config/fcitx5/*",
		"/home/*/.config/fcitx/*",
		"/home/*/.config/ibus/*",
		"/home/*/.mozc/*",
		"/home/*/.config/alacritty/alacritty.toml",
		"/home/*/.config/kitty/kitty.conf",
		"/home/*/.config/wezterm/wezterm.lua",
		"/home/*/.config/ghostty/config",
		"/home/*/.config/Code/User/settings.json",
		"/home/*/.config/Code/User/keybindings.json",
		"/home/*/.config/nvim/init.lua",
		"/home/*/.config/nvim/init.vim",
		"/home/*/.vimrc",
	}
	for _, path := range glob(opts.Root, patterns...) {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		report.Items = append(report.Items, model.Item{
			Kind:     "desktop-config",
			Name:     desktopConfigName(path),
			Path:     displayPath(opts.Root, path),
			Decision: model.DecisionCandidate,
			Reason:   "desktop environment configuration",
		})
	}
}

func scanDconf(ctx context.Context, opts Options, report *model.ScanReport) {
	if opts.Root != "/" {
		return
	}
	if opts.Runner == nil && !commandAvailable("dconf") {
		return
	}
	out, err := runWithOptions(ctx, opts, "dconf", "dump", "/")
	if err != nil {
		return
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return
	}
	report.Desktop.Dconf = strings.Split(text, "\n")
}

func desktopConfigName(path string) string {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))
	if base == "config" && parent != "." && parent != string(filepath.Separator) {
		return parent + "/" + base
	}
	return base
}
