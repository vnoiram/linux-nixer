package scanner

import (
	"bufio"
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type BackupConfigScanner struct{}

func (BackupConfigScanner) Name() string { return "backup-config" }

func (BackupConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	seen := map[string]bool{}
	scanBackupConfigFiles(opts, report, seen)
	scanBackupJobs(opts, report, seen)
	return nil
}

func scanBackupConfigFiles(opts Options, report *model.ScanReport, seen map[string]bool) {
	for _, path := range findBackupFiles(opts.Root) {
		display := displayPath(opts.Root, path)
		addBackupItem(opts, report, seen, path, backupTool(display), backupReason(display), backupDetails(display, readLocalBackupFile(opts.Root, path)))
	}
}

func scanBackupJobs(opts Options, report *model.ScanReport, seen map[string]bool) {
	for _, path := range glob(opts.Root,
		"/etc/systemd/system/*.service",
		"/etc/systemd/system/*.timer",
		"/home/*/.config/systemd/user/*.service",
		"/home/*/.config/systemd/user/*.timer",
		"/etc/cron.d/*",
		"/var/spool/cron/crontabs/*",
	) {
		content := readLocalBackupFile(opts.Root, path)
		display := displayPath(opts.Root, path)
		if !mentionsBackupTool(display + "\n" + content) {
			continue
		}
		details := backupJobDetails(display, content)
		addBackupItem(opts, report, seen, path, detailOrTool(details), "backup or sync job", details)
	}
}

func findBackupFiles(root string) []string {
	var out []string
	for _, pattern := range []string{
		"/home/*/.config/rclone/rclone.conf",
		"/home/*/.config/restic/*",
		"/home/*/.config/borg/*",
		"/home/*/.config/kopia/*",
		"/home/*/.config/syncthing/*",
		"/home/*/.config/duplicati/*",
		"/etc/restic*",
		"/etc/borg*",
		"/etc/kopia*",
		"/etc/rclone*",
		"/etc/timeshift/*",
		"/var/lib/duplicati/*",
		"/var/lib/syncthing/*",
	} {
		for _, path := range glob(root, pattern) {
			info, ok := safeStat(root, path)
			if !ok || info.IsDir() {
				continue
			}
			if isBackupConfigPath(displayPath(root, path)) {
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

func addBackupItem(opts Options, report *model.ScanReport, seen map[string]bool, path, name, reason string, details map[string]string) {
	if seen[path] {
		return
	}
	seen[path] = true
	if name == "" {
		name = filepath.Base(path)
	}
	report.Items = append(report.Items, model.Item{
		Kind:     "backup-config",
		Name:     name,
		Path:     displayPath(opts.Root, path),
		Decision: model.DecisionMigrationNote,
		Reason:   reason,
		Details:  details,
	})
}

func readLocalBackupFile(root, path string) string {
	b, ok := safeReadFile(root, path)
	if !ok {
		return ""
	}
	return string(b)
}

func isBackupConfigPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "rclone") ||
		strings.Contains(lower, "restic") ||
		strings.Contains(lower, "borg") ||
		strings.Contains(lower, "kopia") ||
		strings.Contains(lower, "syncthing") ||
		strings.Contains(lower, "timeshift") ||
		strings.Contains(lower, "duplicati")
}

func backupTool(path string) string {
	lower := strings.ToLower(path)
	for _, tool := range []string{"rclone", "restic", "borg", "kopia", "syncthing", "timeshift", "duplicati", "rsync"} {
		if strings.Contains(lower, tool) {
			return tool
		}
	}
	return ""
}

func backupReason(path string) string {
	tool := backupTool(path)
	if tool == "" {
		return "backup or sync configuration"
	}
	return tool + " backup or sync configuration"
}

func backupDetails(path, content string) map[string]string {
	details := map[string]string{}
	tool := backupTool(path)
	if tool != "" {
		details["tool"] = tool
	}
	switch tool {
	case "rclone":
		mergeDetails(details, rcloneDetails(content))
	case "syncthing":
		mergeDetails(details, syncthingDetails(content))
	case "restic", "borg", "kopia", "duplicati", "timeshift":
		mergeDetails(details, genericBackupConfigDetails(content))
	}
	return emptyNil(details)
}

func rcloneDetails(content string) map[string]string {
	details := map[string]string{}
	remotes := 0
	secretRefs := 0
	remoteTypes := map[string]bool{}
	currentRemote := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			remotes++
			currentRemote = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if isSecretConfigKey(key) || isBackupSecretReference(line) {
			secretRefs++
			continue
		}
		if currentRemote && key == "type" && value != "" {
			remoteTypes[value] = true
		}
	}
	setBackupPositiveDetail(details, "remotes", remotes)
	setBackupPositiveDetail(details, "secret-refs", secretRefs)
	if len(remoteTypes) > 0 {
		details["remote-types"] = strings.Join(sortedDevOpsKeys(remoteTypes), ",")
	}
	return emptyNil(details)
}

func syncthingDetails(content string) map[string]string {
	details := map[string]string{}
	setBackupPositiveDetail(details, "folders", strings.Count(content, "<folder "))
	setBackupPositiveDetail(details, "devices", strings.Count(content, "<device "))
	return emptyNil(details)
}

func genericBackupConfigDetails(content string) map[string]string {
	details := map[string]string{}
	profiles := 0
	repos := 0
	secretRefs := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isBackupSecretReference(line) {
			secretRefs++
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			profiles++
		}
		if strings.Contains(lower, "repository") || strings.Contains(lower, "repo") {
			repos++
		}
	}
	setBackupPositiveDetail(details, "profiles", profiles)
	setBackupPositiveDetail(details, "repositories", repos)
	setBackupPositiveDetail(details, "secret-refs", secretRefs)
	return emptyNil(details)
}

func backupJobDetails(path, content string) map[string]string {
	details := map[string]string{}
	tools := map[string]bool{}
	secretRefs := 0
	schedule := ""
	for _, tool := range []string{"restic", "borg", "kopia", "rclone", "rsync", "syncthing", "timeshift", "duplicati"} {
		if strings.Contains(strings.ToLower(path), tool) {
			tools[tool] = true
		}
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		for _, tool := range []string{"restic", "borg", "kopia", "rclone", "rsync", "syncthing", "timeshift", "duplicati"} {
			if strings.Contains(lower, tool) {
				tools[tool] = true
			}
		}
		if isBackupSecretReference(line) {
			secretRefs++
		}
		if schedule == "" {
			if strings.HasPrefix(line, "OnCalendar=") || strings.HasPrefix(line, "OnBootSec=") || strings.HasPrefix(line, "OnUnitActiveSec=") {
				schedule = line
			} else if strings.Contains(path, "/cron") {
				fields := strings.Fields(line)
				if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
					schedule = fields[0]
				} else if len(fields) >= 6 {
					schedule = strings.Join(fields[:5], " ")
				}
			}
		}
	}
	if len(tools) > 0 {
		details["tools"] = strings.Join(sortedDevOpsKeys(tools), ",")
	}
	if schedule != "" {
		details["schedule"] = schedule
	}
	setBackupPositiveDetail(details, "secret-refs", secretRefs)
	return emptyNil(details)
}

func mentionsBackupTool(content string) bool {
	return backupTool(content) != ""
}

func detailOrTool(details map[string]string) string {
	if details != nil && details["tools"] != "" {
		return details["tools"]
	}
	return "backup-job"
}

func isBackupSecretReference(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "password") ||
		strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key") ||
		strings.Contains(lower, "credential")
}

func setBackupPositiveDetail(details map[string]string, key string, value int) {
	if value > 0 {
		details[key] = strconv.Itoa(value)
	}
}

func mergeDetails(dst, src map[string]string) {
	for key, value := range src {
		dst[key] = value
	}
}
