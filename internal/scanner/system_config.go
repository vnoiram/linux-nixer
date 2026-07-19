package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
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
		"/etc/locale.conf",
		"/etc/timezone",
		"/etc/ssh/sshd_config",
		"/etc/sysctl.conf",
		"/etc/nftables.conf",
		"/etc/ufw/ufw.conf",
		"/etc/default/ufw",
		"/etc/netplan",
		"/etc/NetworkManager/NetworkManager.conf",
		"/etc/resolv.conf",
		"/etc/systemd/resolved.conf",
	} {
		if existsWithSudo(ctx, opts, report, "system-config", path) {
			report.Items = append(report.Items, model.Item{
				Kind:     "os-config",
				Name:     filepath.Base(path),
				Path:     path,
				Decision: model.DecisionCandidate,
				Reason:   systemConfigReason(path),
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
			report.Items = append(report.Items, model.Item{
				Kind:     "os-config",
				Name:     filepath.Base(path),
				Path:     display,
				Decision: decision,
				Reason:   reason,
			})
		}
	}
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
		strings.Contains(path, "resolved.conf"):
		return "network configuration"
	case strings.Contains(path, "nftables") ||
		strings.Contains(path, "/ufw/") ||
		strings.Contains(path, "/default/ufw"):
		return "firewall configuration"
	case strings.Contains(path, "/nginx/") ||
		strings.Contains(path, "/apache2/"):
		return "web server configuration"
	case strings.Contains(path, "sysctl") ||
		strings.Contains(path, "/modprobe.d/") ||
		strings.Contains(path, "/udev/"):
		return "kernel or device tuning"
	case strings.Contains(path, "/logrotate"):
		return "log rotation configuration"
	case strings.Contains(path, "ssh/sshd_config"):
		return "ssh daemon configuration"
	case strings.Contains(path, "fstab"):
		return "filesystem mount configuration"
	case strings.Contains(path, "sudoers"):
		return "privilege configuration"
	case strings.Contains(path, "locale") || strings.Contains(path, "timezone"):
		return "localization configuration"
	default:
		return "system configuration"
	}
}
