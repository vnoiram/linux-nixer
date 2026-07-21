package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type SystemConfigScanner struct{}

func (SystemConfigScanner) Name() string { return "system-config" }

func (SystemConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	scanSystemConfigFiles(ctx, opts, report)
	scanSystemConfigGlobs(opts, report)
	scanSystemServices(opts, report)
	return nil
}

func scanSystemConfigFiles(ctx context.Context, opts Options, report *model.ScanReport) {
	for _, path := range []string{
		"/etc/fstab",
		"/etc/hosts",
		"/etc/sudoers",
		"/etc/login.defs",
		"/etc/default/useradd",
		"/etc/adduser.conf",
		"/etc/locale.conf",
		"/etc/timezone",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/sysctl.conf",
		"/etc/nftables.conf",
		"/etc/ufw/ufw.conf",
		"/etc/default/ufw",
		"/etc/netplan",
		"/etc/NetworkManager/NetworkManager.conf",
		"/etc/resolv.conf",
		"/etc/systemd/resolved.conf",
		"/etc/fail2ban/jail.local",
		"/etc/audit/auditd.conf",
		"/var/lib/tailscale",
		"/var/lib/zerotier-one",
		"/etc/tailscale",
		"/etc/zerotier-one",
	} {
		if existsWithSudo(ctx, opts, report, "system-config", path) {
			details := readSystemConfigDetails(ctx, opts, report, path)
			report.Items = append(report.Items, model.Item{
				Kind:     "os-config",
				Name:     filepath.Base(path),
				Path:     path,
				Decision: model.DecisionCandidate,
				Reason:   systemConfigReason(path),
				Details:  details,
			})
		}
	}
}

func scanSystemConfigGlobs(opts Options, report *model.ScanReport) {
	for _, pattern := range []string{
		"/etc/sysctl.d/*.conf",
		"/etc/modprobe.d/*.conf",
		"/etc/udev/rules.d/*.rules",
		"/etc/logrotate.d/*",
		"/etc/sudoers.d/*",
		"/etc/pam.d/*",
		"/etc/security/*.conf",
		"/etc/security/limits.d/*.conf",
		"/etc/polkit-1/rules.d/*",
		"/usr/local/share/polkit-1/rules.d/*",
		"/etc/fail2ban/jail.d/*.conf",
		"/etc/audit/rules.d/*.rules",
		"/etc/apparmor.d/*",
		"/etc/apparmor.d/local/*",
		"/etc/ssh/ssh_config.d/*.conf",
		"/etc/wireguard/*.conf",
		"/etc/openvpn/*.conf",
		"/etc/openvpn/*/*.conf",
		"/home/*/.config/wireguard/*.conf",
		"/etc/netplan/*.yaml",
		"/etc/NetworkManager/system-connections/*",
		"/etc/nginx/sites-enabled/*",
		"/etc/apache2/sites-enabled/*",
	} {
		for _, path := range glob(opts.Root, pattern) {
			display := displayPath(opts.Root, path)
			decision := model.DecisionCandidate
			reason := systemConfigReason(display)
			if strings.Contains(display, "/NetworkManager/system-connections/") {
				decision = model.DecisionMigrationNote
				reason = "network connection profile may contain credentials"
			}
			details := systemConfigDetails(display, readLocalFile(path))
			report.Items = append(report.Items, model.Item{
				Kind:     "os-config",
				Name:     filepath.Base(path),
				Path:     display,
				Decision: decision,
				Reason:   reason,
				Details:  details,
			})
		}
	}
}

func readSystemConfigDetails(ctx context.Context, opts Options, report *model.ScanReport, displayPath string) map[string]string {
	b, err := readFile(ctx, opts, report, "system-config", displayPath)
	if err != nil {
		return nil
	}
	return systemConfigDetails(displayPath, string(b))
}

func readLocalFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func systemConfigDetails(path, content string) map[string]string {
	if content == "" {
		return nil
	}
	switch {
	case strings.HasSuffix(path, "/etc/hosts"):
		return hostsDetails(content)
	case strings.HasSuffix(path, "/etc/resolv.conf"):
		return resolvDetails(content)
	case strings.HasSuffix(path, "/etc/systemd/resolved.conf"):
		return keyValueDetails(content, []string{"DNS", "FallbackDNS", "Domains", "DNSSEC", "DNSOverTLS", "MulticastDNS"})
	case strings.Contains(path, "/netplan/") && strings.HasSuffix(path, ".yaml"):
		return netplanDetails(content)
	case strings.Contains(path, "/NetworkManager/system-connections/"):
		return networkManagerConnectionDetails(content)
	case strings.HasSuffix(path, "/etc/NetworkManager/NetworkManager.conf"):
		return keyValueDetails(content, []string{"plugins", "dns", "managed", "rc-manager"})
	case strings.HasSuffix(path, "/etc/ufw/ufw.conf") || strings.HasSuffix(path, "/etc/default/ufw"):
		return keyValueDetails(content, []string{"ENABLED", "IPV6", "DEFAULT_INPUT_POLICY", "DEFAULT_OUTPUT_POLICY", "DEFAULT_FORWARD_POLICY"})
	case strings.HasSuffix(path, "/etc/nftables.conf"):
		return nftablesDetails(content)
	case strings.HasSuffix(path, "/etc/ssh/sshd_config"):
		return sshdDetails(content)
	case strings.HasSuffix(path, "/etc/ssh/ssh_config") || strings.Contains(path, "/etc/ssh/ssh_config.d/"):
		return sshClientConfigDetails(content)
	case strings.Contains(path, "/wireguard/") && strings.HasSuffix(path, ".conf"):
		return wireGuardDetails(content)
	case strings.Contains(path, "/openvpn/") && strings.HasSuffix(path, ".conf"):
		return openVPNDetails(content)
	case strings.HasSuffix(path, "/etc/sudoers") || strings.Contains(path, "/etc/sudoers.d/"):
		return sudoersDetails(content)
	case strings.HasSuffix(path, "/etc/login.defs"):
		return loginDefsDetails(content)
	case strings.HasSuffix(path, "/etc/default/useradd") || strings.HasSuffix(path, "/etc/adduser.conf"):
		return keyValueDetails(content, []string{"GROUP", "HOME", "SHELL", "SKEL", "CREATE_HOME", "DSHELL", "DHOME", "FIRST_UID", "LAST_UID", "FIRST_GID", "LAST_GID", "USERGROUPS"})
	case strings.Contains(path, "/etc/pam.d/"):
		return pamDetails(content)
	case strings.Contains(path, "/etc/security/"):
		return securityConfDetails(content)
	case strings.Contains(path, "/polkit-1/rules.d/"):
		return polkitDetails(content)
	case strings.Contains(path, "/fail2ban/"):
		return fail2banDetails(content)
	case strings.Contains(path, "/audit/"):
		return auditDetails(content)
	case strings.Contains(path, "/apparmor.d/"):
		return apparmorDetails(content)
	default:
		return nil
	}
}

func hostsDetails(content string) map[string]string {
	entries := 0
	names := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := stripInlineComment(sc.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entries++
		for _, name := range fields[1:] {
			names[name] = true
		}
	}
	return countDetails("entries", entries, "hostnames", len(names))
}

func resolvDetails(content string) map[string]string {
	details := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		fields := strings.Fields(stripInlineComment(sc.Text()))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			appendDetail(details, "nameservers", fields[1])
		case "search":
			appendDetail(details, "search", strings.Join(fields[1:], " "))
		case "domain":
			appendDetail(details, "domain", fields[1])
		}
	}
	return emptyNil(details)
}

func netplanDetails(content string) map[string]string {
	details := map[string]string{}
	interfaceTypes := map[string]bool{}
	for _, line := range linesWithoutComments(content) {
		trimmed := strings.TrimSpace(line)
		key, value, ok := strings.Cut(trimmed, ":")
		if ok {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			switch key {
			case "renderer":
				setDetail(details, "renderer", value)
			case "ethernets", "wifis", "bonds", "bridges", "vlans", "tunnels":
				interfaceTypes[key] = true
			case "dhcp4", "dhcp6":
				setDetail(details, key, value)
			case "addresses", "routes", "nameservers":
				setDetail(details, key, "present")
			}
		}
	}
	if len(interfaceTypes) > 0 {
		details["interface-types"] = strings.Join(sortedKeys(interfaceTypes), ",")
	}
	return emptyNil(details)
}

func networkManagerConnectionDetails(content string) map[string]string {
	details := map[string]string{}
	allowed := map[string]string{
		"id":             "id",
		"type":           "type",
		"interface-name": "interface-name",
		"autoconnect":    "autoconnect",
		"method":         "method",
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if isSecretConfigKey(key) {
			continue
		}
		if outKey, ok := allowed[key]; ok {
			setDetail(details, outKey, value)
		}
	}
	return emptyNil(details)
}

func keyValueDetails(content string, keys []string) map[string]string {
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[strings.ToLower(key)] = true
	}
	details := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" || isSecretConfigKey(key) || !allowed[strings.ToLower(key)] {
			continue
		}
		setDetail(details, key, value)
	}
	return emptyNil(details)
}

func nftablesDetails(content string) map[string]string {
	tables, chains, rules := 0, 0, 0
	for _, line := range linesWithoutComments(content) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "table":
			tables++
		case "chain":
			chains++
		default:
			if strings.Contains(line, " accept") || strings.Contains(line, " drop") || strings.Contains(line, " reject") || strings.Contains(line, " dnat ") || strings.Contains(line, " snat ") {
				rules++
			}
		}
	}
	return countDetails("tables", tables, "chains", chains, "rules", rules)
}

func sshdDetails(content string) map[string]string {
	details := map[string]string{}
	allowed := map[string]bool{
		"port":                   true,
		"permitrootlogin":        true,
		"passwordauthentication": true,
		"pubkeyauthentication":   true,
		"allowusers":             true,
		"allowgroups":            true,
		"denyusers":              true,
		"denygroups":             true,
		"x11forwarding":          true,
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		if !allowed[strings.ToLower(key)] || isSecretConfigKey(key) {
			if strings.ToLower(key) != "passwordauthentication" {
				continue
			}
		}
		value := strings.TrimSpace(strings.Join(fields[1:], " "))
		if value != "" {
			details[key] = value
		}
	}
	return emptyNil(details)
}

func wireGuardDetails(content string) map[string]string {
	details := map[string]string{}
	peers := 0
	endpoints := 0
	allowedIPs := 0
	secretRefs := 0
	hasDNS := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "privatekey", "presharedkey":
			secretRefs++
		case "publickey":
			peers++
		case "endpoint":
			if value != "" {
				endpoints++
			}
		case "allowedips":
			if value != "" {
				allowedIPs += len(strings.Split(value, ","))
			}
		case "dns":
			hasDNS = value != ""
		}
	}
	setBackupPositiveDetail(details, "peers", peers)
	setBackupPositiveDetail(details, "endpoints", endpoints)
	setBackupPositiveDetail(details, "allowed-ips", allowedIPs)
	setBackupPositiveDetail(details, "secret-refs", secretRefs)
	if hasDNS {
		details["dns"] = "present"
	}
	return emptyNil(details)
}

func openVPNDetails(content string) map[string]string {
	details := map[string]string{}
	remotes := 0
	routes := 0
	secretRefs := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "remote":
			remotes++
		case "route", "redirect-gateway":
			routes++
		case "auth-user-pass", "tls-auth", "tls-crypt", "secret", "pkcs12", "key":
			secretRefs++
		}
	}
	setBackupPositiveDetail(details, "remotes", remotes)
	setBackupPositiveDetail(details, "routes", routes)
	setBackupPositiveDetail(details, "secret-refs", secretRefs)
	return emptyNil(details)
}

func sudoersDetails(content string) map[string]string {
	userRules, groupRules, nopasswd, includes := 0, 0, 0, 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "@include") || strings.HasPrefix(trimmed, "#include"):
			includes++
		case strings.HasPrefix(trimmed, "#"):
			continue
		case strings.HasPrefix(trimmed, "%"):
			groupRules++
			if strings.Contains(strings.ToUpper(trimmed), "NOPASSWD") {
				nopasswd++
			}
		default:
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 && strings.Contains(fields[1], "=") {
				userRules++
				if strings.Contains(strings.ToUpper(trimmed), "NOPASSWD") {
					nopasswd++
				}
			}
		}
	}
	return countDetails("user-rules", userRules, "group-rules", groupRules, "nopasswd-rules", nopasswd, "includes", includes)
}

func loginDefsDetails(content string) map[string]string {
	details := map[string]string{}
	allowed := map[string]bool{
		"UID_MIN":        true,
		"UID_MAX":        true,
		"GID_MIN":        true,
		"GID_MAX":        true,
		"SYS_UID_MIN":    true,
		"SYS_UID_MAX":    true,
		"SYS_GID_MIN":    true,
		"SYS_GID_MAX":    true,
		"PASS_MAX_DAYS":  true,
		"PASS_MIN_DAYS":  true,
		"PASS_WARN_AGE":  true,
		"UMASK":          true,
		"ENCRYPT_METHOD": true,
	}
	for _, line := range linesWithoutComments(content) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		if allowed[key] && !isSecretConfigKey(key) {
			setDetail(details, key, strings.Join(fields[1:], " "))
		}
	}
	return emptyNil(details)
}

func pamDetails(content string) map[string]string {
	modules := map[string]bool{}
	important := map[string]bool{}
	rules := 0
	for _, line := range linesWithoutComments(content) {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		rules++
		module := filepath.Base(fields[2])
		modules[module] = true
		switch module {
		case "pam_faillock.so", "pam_u2f.so", "pam_google_authenticator.so", "pam_limits.so", "pam_systemd.so", "pam_sss.so", "pam_ldap.so", "pam_mount.so":
			important[module] = true
		}
	}
	details := countDetails("rules", rules)
	if details == nil {
		details = map[string]string{}
	}
	if len(modules) > 0 {
		details["modules"] = limitedJoinedKeys(modules, 8)
	}
	if len(important) > 0 {
		details["important-modules"] = limitedJoinedKeys(important, 8)
	}
	return emptyNil(details)
}

func securityConfDetails(content string) map[string]string {
	entries := 0
	domains := map[string]bool{}
	for _, line := range linesWithoutComments(content) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entries++
		domains[fields[0]] = true
	}
	details := countDetails("entries", entries)
	if details == nil {
		details = map[string]string{}
	}
	if len(domains) > 0 {
		details["domains"] = limitedJoinedKeys(domains, 8)
	}
	return emptyNil(details)
}

func polkitDetails(content string) map[string]string {
	rules := strings.Count(content, "polkit.addRule")
	adminRules := strings.Count(content, "polkit.addAdminRule")
	mentionsWheel := strings.Contains(content, "unix-group:wheel")
	mentionsSudo := strings.Contains(content, "unix-group:sudo")
	details := countDetails("rules", rules, "admin-rules", adminRules)
	if details == nil {
		details = map[string]string{}
	}
	if mentionsWheel {
		details["mentions-wheel"] = "true"
	}
	if mentionsSudo {
		details["mentions-sudo"] = "true"
	}
	return emptyNil(details)
}

func fail2banDetails(content string) map[string]string {
	details := map[string]string{}
	enabledJails := 0
	currentSection := ""
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			if currentSection != "DEFAULT" && currentSection != "" {
				appendDetail(details, "jails", currentSection)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if currentSection != "" && currentSection != "DEFAULT" && strings.EqualFold(key, "enabled") && strings.EqualFold(value, "true") {
			enabledJails++
		}
		switch key {
		case "bantime", "findtime", "maxretry", "backend":
			setDetail(details, key, value)
		}
	}
	if enabledJails > 0 {
		details["enabled-jails"] = strconv.Itoa(enabledJails)
	}
	return emptyNil(details)
}

func auditDetails(content string) map[string]string {
	rules, watches, syscalls := 0, 0, 0
	settings := map[string]string{}
	for _, line := range linesWithoutComments(content) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "-w":
			rules++
			watches++
		case fields[0] == "-a":
			rules++
			if strings.Contains(line, "-S ") {
				syscalls++
			}
		default:
			if key, value, ok := strings.Cut(line, "="); ok {
				key = strings.TrimSpace(key)
				value = strings.TrimSpace(value)
				if stringIn([]string{"log_file", "max_log_file", "num_logs", "flush", "freq"}, key) && !isSecretConfigKey(key) {
					settings[key] = value
				}
			}
		}
	}
	details := countDetails("rules", rules, "watches", watches, "syscall-rules", syscalls)
	if details == nil {
		details = map[string]string{}
	}
	for key, value := range settings {
		setDetail(details, key, value)
	}
	return emptyNil(details)
}

func apparmorDetails(content string) map[string]string {
	profiles := 0
	includes := 0
	capabilities := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "profile "):
			profiles++
		case strings.HasPrefix(trimmed, "#include") || strings.HasPrefix(trimmed, "include "):
			includes++
		case strings.HasPrefix(trimmed, "capability "):
			capabilities++
		}
	}
	return countDetails("profiles", profiles, "includes", includes, "capabilities", capabilities)
}

func countDetails(pairs ...any) map[string]string {
	details := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		key, _ := pairs[i].(string)
		value, _ := pairs[i+1].(int)
		if key != "" && value > 0 {
			details[key] = strconv.Itoa(value)
		}
	}
	return emptyNil(details)
}

func linesWithoutComments(content string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := stripInlineComment(sc.Text())
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func stripInlineComment(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		return before
	}
	return line
}

func setDetail(details map[string]string, key, value string) {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if key == "" || value == "" || isSecretConfigKey(key) {
		return
	}
	details[key] = value
}

func appendDetail(details map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if key == "" || value == "" || isSecretConfigKey(key) {
		return
	}
	if existing := details[key]; existing != "" {
		if !strings.Contains(","+existing+",", ","+value+",") {
			details[key] = existing + "," + value
		}
		return
	}
	details[key] = value
}

func sortedKeys(values map[string]bool) []string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func limitedJoinedKeys(values map[string]bool, limit int) string {
	keys := sortedKeys(values)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	return strings.Join(keys, ",")
}

func stringIn(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isSecretConfigKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "password") ||
		strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "psk") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "private-key") ||
		strings.Contains(lower, "identity") ||
		strings.Contains(lower, "credential")
}

func emptyNil(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	return details
}

func scanSystemServices(opts Options, report *model.ScanReport) {
	for _, path := range glob(opts.Root, "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/home/*/.config/systemd/user/*.service") {
		service := model.Service{
			Manager:  "systemd",
			Name:     filepath.Base(path),
			Path:     displayPath(opts.Root, path),
			Decision: model.DecisionCandidate,
		}
		applySystemdDetails(path, &service)
		report.Services = append(report.Services, service)
	}
	for _, path := range glob(opts.Root, "/etc/cron.d/*", "/var/spool/cron/crontabs/*") {
		service := model.Service{
			Manager:  "cron",
			Name:     filepath.Base(path),
			Path:     displayPath(opts.Root, path),
			Decision: model.DecisionCandidate,
		}
		applyCronDetails(service.Path, path, &service)
		report.Services = append(report.Services, service)
	}
}

func applySystemdDetails(path string, service *model.Service) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch section + "." + key {
		case "Unit.Description":
			if service.Description == "" {
				service.Description = value
			}
		case "Service.User":
			if service.User == "" {
				service.User = value
			}
		case "Service.WorkingDirectory":
			if service.WorkingDirectory == "" {
				service.WorkingDirectory = value
			}
		case "Service.ExecStart":
			if service.ExecStart == "" {
				service.ExecStart = value
			}
		case "Service.EnvironmentFile":
			service.EnvironmentFiles = appendSystemdWords(service.EnvironmentFiles, value)
		case "Install.WantedBy":
			service.WantedBy = appendSystemdWords(service.WantedBy, value)
		case "Timer.OnCalendar":
			if service.Schedule == "" {
				service.Schedule = "OnCalendar=" + value
			}
		case "Timer.OnBootSec":
			if service.Schedule == "" {
				service.Schedule = "OnBootSec=" + value
			}
		case "Timer.OnUnitActiveSec":
			if service.Schedule == "" {
				service.Schedule = "OnUnitActiveSec=" + value
			}
		}
	}
}

func appendSystemdWords(out []string, value string) []string {
	for _, word := range strings.Fields(value) {
		word = strings.TrimPrefix(word, "-")
		if word != "" {
			out = append(out, word)
		}
	}
	return out
}

func applyCronDetails(displayPath, path string, service *model.Service) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	spoolUser := ""
	if strings.HasPrefix(displayPath, "/var/spool/cron/crontabs/") {
		spoolUser = filepath.Base(path)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], "@") {
			service.Schedule = fields[0]
			rest := fields[1:]
			if spoolUser != "" {
				service.User = spoolUser
				service.ExecStart = strings.Join(rest, " ")
			} else if len(rest) >= 1 {
				service.User = rest[0]
				service.ExecStart = strings.Join(rest[1:], " ")
			}
			return
		}
		if len(fields) < 6 {
			continue
		}
		service.Schedule = strings.Join(fields[:5], " ")
		if spoolUser != "" {
			service.User = spoolUser
			service.ExecStart = strings.Join(fields[5:], " ")
		} else if len(fields) >= 7 {
			service.User = fields[5]
			service.ExecStart = strings.Join(fields[6:], " ")
		}
		return
	}
}

func systemConfigReason(path string) string {
	switch {
	case strings.Contains(path, "/netplan") ||
		strings.Contains(path, "/NetworkManager/") ||
		strings.HasSuffix(path, "/resolv.conf") ||
		strings.Contains(path, "resolved.conf") ||
		strings.Contains(path, "/wireguard/") ||
		strings.Contains(path, "/openvpn/") ||
		strings.Contains(path, "tailscale") ||
		strings.Contains(path, "zerotier"):
		return "network configuration"
	case strings.Contains(path, "nftables") ||
		strings.Contains(path, "/ufw/") ||
		strings.Contains(path, "/default/ufw"):
		return "firewall configuration"
	case strings.Contains(path, "/nginx/") ||
		strings.Contains(path, "/apache2/"):
		return "web server configuration"
	case strings.Contains(path, "sudoers") ||
		strings.Contains(path, "/pam.d/") ||
		strings.Contains(path, "/security/") ||
		strings.Contains(path, "login.defs") ||
		strings.Contains(path, "/default/useradd") ||
		strings.Contains(path, "adduser.conf") ||
		strings.Contains(path, "/polkit-1/") ||
		strings.Contains(path, "/fail2ban/") ||
		strings.Contains(path, "/audit/") ||
		strings.Contains(path, "/apparmor.d/"):
		return "auth and security configuration"
	case strings.Contains(path, "sysctl") ||
		strings.Contains(path, "/modprobe.d/") ||
		strings.Contains(path, "/udev/"):
		return "kernel or device tuning"
	case strings.Contains(path, "/logrotate"):
		return "log rotation configuration"
	case strings.Contains(path, "ssh/sshd_config"):
		return "ssh daemon configuration"
	case strings.Contains(path, "ssh/ssh_config"):
		return "ssh client configuration"
	case strings.Contains(path, "fstab"):
		return "filesystem mount configuration"
	case strings.Contains(path, "locale") || strings.Contains(path, "timezone"):
		return "localization configuration"
	default:
		return "system configuration"
	}
}
