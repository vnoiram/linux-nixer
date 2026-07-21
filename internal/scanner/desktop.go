package scanner

import (
	"context"
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
	scanGUIProfiles(opts, report)
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
		if info, ok := safeStat(opts.Root, path); ok && !info.IsDir() {
			report.Desktop.Fonts = append(report.Desktop.Fonts, displayPath(opts.Root, path))
		}
	}
	for _, path := range glob(opts.Root, "/usr/share/themes/*", "/home/*/.themes/*", "/usr/share/icons/*", "/home/*/.icons/*") {
		if info, ok := safeStat(opts.Root, path); ok && info.IsDir() {
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
		if info, ok := safeStat(opts.Root, path); !ok || info.IsDir() {
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

func scanGUIProfiles(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root,
		"/home/*/.mozilla/firefox/profiles.ini",
		"/home/*/.mozilla/firefox/*.default*",
		"/home/*/.config/google-chrome/Default",
		"/home/*/.config/google-chrome/Profile *",
		"/home/*/.config/chromium/Default",
		"/home/*/.config/chromium/Profile *",
		"/home/*/.config/BraveSoftware/Brave-Browser/Default",
		"/home/*/.config/BraveSoftware/Brave-Browser/Profile *",
	) {
		addDesktopItem(opts, report, path, "browser-profile", model.DecisionMigrationNote, "browser profile may contain cookies, history, saved sessions, and credentials")
	}
	for _, path := range glob(opts.Root,
		"/home/*/.mozilla/firefox/*.default*/extensions/*",
		"/home/*/.config/google-chrome/*/Extensions/*",
		"/home/*/.config/chromium/*/Extensions/*",
		"/home/*/.config/BraveSoftware/Brave-Browser/*/Extensions/*",
	) {
		addDesktopItem(opts, report, path, "browser-extension", model.DecisionMigrationNote, "browser extension marker; review sync/export strategy manually")
	}
	for _, path := range glob(opts.Root,
		"/home/*/.config/Code/User/settings.json",
		"/home/*/.config/Code/User/keybindings.json",
		"/home/*/.config/Code/User/snippets",
		"/home/*/.config/VSCodium/User/settings.json",
		"/home/*/.config/VSCodium/User/keybindings.json",
		"/home/*/.config/VSCodium/User/snippets",
		"/home/*/.vscode/extensions/*",
		"/home/*/.vscode-oss/extensions/*",
		"/home/*/.config/JetBrains/*",
		"/home/*/.local/share/JetBrains/*",
	) {
		addDesktopItem(opts, report, path, "editor-profile", model.DecisionCandidate, "editor settings, extensions, or IDE profile")
	}
}

func addDesktopItem(opts Options, report *model.ScanReport, path string, kind string, decision model.Decision, reason string) {
	if info, ok := safeStat(opts.Root, path); !ok {
		return
	} else if !info.IsDir() && kind != "editor-profile" && kind != "browser-extension" && !strings.HasSuffix(path, "profiles.ini") {
		return
	}
	display := displayPath(opts.Root, path)
	for _, item := range report.Items {
		if item.Path == display && item.Kind == kind {
			return
		}
	}
	report.Items = append(report.Items, model.Item{
		Kind:     kind,
		Name:     desktopConfigName(path),
		Path:     display,
		Decision: decision,
		Reason:   reason,
	})
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
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		// dconf covers the whole GSettings database for this user, which in
		// practice can include app-stored tokens/credentials (e.g. some
		// sync/backup tools and GNOME Online Accounts caches keep secrets
		// here) — redact secret-like lines the same way other content-based
		// scanners in this package do, instead of embedding raw values.
		if isSecretReference(line) {
			lines[i] = "[secret-like line redacted]"
		}
	}
	report.Desktop.Dconf = lines
}

func desktopConfigName(path string) string {
	base := filepath.Base(path)
	parent := filepath.Base(filepath.Dir(path))
	if base == "config" && parent != "." && parent != string(filepath.Separator) {
		return parent + "/" + base
	}
	return base
}
