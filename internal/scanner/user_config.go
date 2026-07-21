package scanner

import (
	"bufio"
	"context"
	"path/filepath"
	"strings"

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
		"/home/*/.ssh/authorized_keys",
		"/home/*/.ssh/known_hosts",
		"/home/*/.gnupg/gpg.conf",
		"/home/*/.tmux.conf",
		"/home/*/.config/starship.toml",
	) {
		addUserConfigItem(opts, report, path, "user-config", "user tool configuration")
	}
	for _, path := range glob(opts.Root,
		"/home/*/.password-store",
		"/home/*/.local/share/keyrings",
		"/home/*/.gnupg",
		"/home/*/.pki",
		"/home/*/.local/share/kwalletd",
		"/home/*/.kde/share/apps/kwallet",
	) {
		addUserConfigItemWithDecision(opts, report, path, "credential-store", "credential or key store marker; migrate manually", model.DecisionMigrationNote)
	}
}

func addUserConfigItem(opts Options, report *model.ScanReport, path, kind, reason string) {
	addUserConfigItemWithDecision(opts, report, path, kind, reason, model.DecisionCandidate)
}

func addUserConfigItemWithDecision(opts Options, report *model.ScanReport, path, kind, reason string, decision model.Decision) {
	if info, ok := safeStat(opts.Root, path); !ok {
		return
	} else if info.IsDir() && kind != "shell-plugin" && kind != "credential-store" {
		return
	}
	display := displayPath(opts.Root, path)
	report.Items = append(report.Items, model.Item{
		Kind:     kind,
		Name:     userConfigName(path),
		Path:     display,
		Decision: decision,
		Reason:   reason,
		Details:  userConfigDetails(display, readLocalFile(opts.Root, path)),
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

func userConfigDetails(path, content string) map[string]string {
	switch {
	case strings.HasSuffix(path, "/.ssh/config"):
		return sshClientConfigDetails(content)
	case strings.HasSuffix(path, "/.ssh/authorized_keys"):
		return authorizedKeysDetails(content)
	case strings.HasSuffix(path, "/.ssh/known_hosts"):
		return knownHostsDetails(content)
	case strings.Contains(path, "/.password-store"):
		return map[string]string{"store": "password-store"}
	case strings.Contains(path, "/keyrings"):
		return map[string]string{"store": "keyrings"}
	case strings.Contains(path, "/.gnupg"):
		return map[string]string{"store": "gnupg"}
	case strings.Contains(path, "/.pki"):
		return map[string]string{"store": "pki"}
	case strings.Contains(path, "kwallet"):
		return map[string]string{"store": "kwallet"}
	default:
		return nil
	}
}

func sshClientConfigDetails(content string) map[string]string {
	details := map[string]string{}
	hosts := 0
	identityFiles := 0
	markers := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch key {
		case "host":
			if len(fields) > 1 {
				hosts++
			}
		case "identityfile":
			identityFiles++
		case "proxyjump", "proxycommand", "forwardagent", "port", "user":
			markers[key] = true
		}
	}
	setBackupPositiveDetail(details, "hosts", hosts)
	setBackupPositiveDetail(details, "identity-files", identityFiles)
	if len(markers) > 0 {
		details["markers"] = strings.Join(sortedKeys(markers), ",")
	}
	return emptyNil(details)
}

func authorizedKeysDetails(content string) map[string]string {
	details := map[string]string{}
	keys := 0
	restricted := 0
	keyTypes := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		keyType := firstSSHKeyType(fields)
		if keyType == "" {
			continue
		}
		keys++
		keyTypes[keyType] = true
		prefix := strings.Join(fields[:indexOfField(fields, keyType)], " ")
		if strings.Contains(prefix, "command=") || strings.Contains(prefix, "from=") || strings.Contains(prefix, "restrict") {
			restricted++
		}
	}
	setBackupPositiveDetail(details, "keys", keys)
	setBackupPositiveDetail(details, "restricted-keys", restricted)
	if len(keyTypes) > 0 {
		details["key-types"] = strings.Join(sortedKeys(keyTypes), ",")
	}
	return emptyNil(details)
}

func knownHostsDetails(content string) map[string]string {
	details := map[string]string{}
	entries := 0
	hashed := 0
	keyTypes := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		entries++
		if strings.HasPrefix(fields[0], "|1|") {
			hashed++
		}
		if isSSHKeyType(fields[1]) {
			keyTypes[fields[1]] = true
		}
	}
	setBackupPositiveDetail(details, "entries", entries)
	setBackupPositiveDetail(details, "hashed-hosts", hashed)
	if len(keyTypes) > 0 {
		details["key-types"] = strings.Join(sortedKeys(keyTypes), ",")
	}
	return emptyNil(details)
}

func firstSSHKeyType(fields []string) string {
	for _, field := range fields {
		if isSSHKeyType(field) {
			return field
		}
	}
	return ""
}

func isSSHKeyType(value string) bool {
	return strings.HasPrefix(value, "ssh-") || strings.HasPrefix(value, "ecdsa-") || value == "sk-ssh-ed25519@openssh.com" || value == "sk-ecdsa-sha2-nistp256@openssh.com"
}

func indexOfField(fields []string, want string) int {
	for i, field := range fields {
		if field == want {
			return i
		}
	}
	return len(fields)
}
