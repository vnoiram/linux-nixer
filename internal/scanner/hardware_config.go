package scanner

import (
	"bufio"
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type HardwareConfigScanner struct{}

func (HardwareConfigScanner) Name() string { return "hardware-config" }

func (HardwareConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	seen := map[string]bool{}
	scanHardwareFiles(opts, report, seen)
	return nil
}

func scanHardwareFiles(opts Options, report *model.ScanReport, seen map[string]bool) {
	for _, path := range findHardwareConfigFiles(opts.Root) {
		display := displayPath(opts.Root, path)
		content := readLocalHardwareFile(opts.Root, path)
		addHardwareItem(opts, report, seen, path, hardwareName(display), hardwareReason(display), hardwareDetails(display, content))
	}
}

func findHardwareConfigFiles(root string) []string {
	var out []string
	for _, pattern := range []string{
		"/etc/cups/printers.conf",
		"/etc/cups/classes.conf",
		"/etc/cups/client.conf",
		"/etc/cups/ppd/*.ppd",
		"/etc/bluetooth/main.conf",
		"/var/lib/bluetooth/*/*/info",
		"/etc/sane.d/dll.conf",
		"/etc/sane.d/*.conf",
		"/etc/pipewire/*.conf",
		"/etc/pipewire/*.lua",
		"/etc/pipewire/*/*.conf",
		"/etc/pipewire/*/*.lua",
		"/etc/pulse/*.conf",
		"/etc/pulse/*.pa",
		"/etc/pulse/*/*.conf",
		"/etc/pulse/*/*.pa",
		"/etc/asound.conf",
		"/home/*/.config/pipewire/*.conf",
		"/home/*/.config/pipewire/*.lua",
		"/home/*/.config/pipewire/*/*.conf",
		"/home/*/.config/pipewire/*/*.lua",
		"/home/*/.config/pulse/*.conf",
		"/home/*/.config/pulse/*.pa",
		"/home/*/.config/pulse/*/*.conf",
		"/home/*/.config/pulse/*/*.pa",
		"/home/*/.asoundrc",
		"/etc/fprintd.conf",
		"/var/lib/fprint/*",
		"/etc/u2f_mappings",
		"/etc/Yubico/*",
		"/etc/yubico/*",
		"/etc/pcsc/*",
		"/etc/opensc.conf",
		"/etc/fwupd/*.conf",
		"/etc/fwupd/*/*.conf",
		"/etc/tlp.conf",
		"/etc/tlp.d/*.conf",
		"/etc/UPower/UPower.conf",
		"/etc/keyd/*.conf",
		"/etc/kanata/*.kbd",
		"/etc/input-remapper-2/*",
		"/home/*/.config/input-remapper-2/*",
		"/home/*/.config/solaar/*",
		"/home/*/.config/xremap/*.yml",
		"/home/*/.config/xremap/*.yaml",
	} {
		for _, path := range glob(root, pattern) {
			info, ok := safeStat(root, path)
			if !ok || info.IsDir() {
				continue
			}
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func addHardwareItem(opts Options, report *model.ScanReport, seen map[string]bool, path, name, reason string, details map[string]string) {
	if seen[path] {
		return
	}
	seen[path] = true
	if name == "" {
		name = filepath.Base(path)
	}
	report.Items = append(report.Items, model.Item{
		Kind:     "hardware-config",
		Name:     name,
		Path:     displayPath(opts.Root, path),
		Decision: model.DecisionMigrationNote,
		Reason:   reason,
		Details:  details,
	})
}

func readLocalHardwareFile(root, path string) string {
	b, ok := safeReadFile(root, path)
	if !ok {
		return ""
	}
	return string(b)
}

func hardwareName(path string) string {
	switch hardwareCategory(path) {
	case "printer":
		return "cups"
	case "bluetooth":
		return "bluetooth"
	case "scanner":
		return "sane"
	case "audio":
		return audioTool(path)
	case "security-device":
		return securityDeviceTool(path)
	case "power-firmware":
		return powerFirmwareTool(path)
	case "input-device":
		return inputDeviceTool(path)
	default:
		return filepath.Base(path)
	}
}

func hardwareReason(path string) string {
	switch hardwareCategory(path) {
	case "printer":
		return "printer configuration"
	case "bluetooth":
		return "bluetooth controller or paired device marker"
	case "scanner":
		return "scanner backend configuration"
	case "audio":
		return "audio profile or server configuration"
	case "security-device":
		return "security device or biometric configuration"
	case "power-firmware":
		return "power management or firmware configuration"
	case "input-device":
		return "input device remapping or peripheral configuration"
	default:
		return "hardware or peripheral configuration"
	}
}

func hardwareCategory(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/etc/cups/"):
		return "printer"
	case strings.Contains(lower, "/etc/bluetooth/") || strings.Contains(lower, "/var/lib/bluetooth/"):
		return "bluetooth"
	case strings.Contains(lower, "/etc/sane.d/"):
		return "scanner"
	case strings.Contains(lower, "pipewire") || strings.Contains(lower, "/pulse/") || strings.HasSuffix(lower, "/.asoundrc") || strings.HasSuffix(lower, "/asound.conf"):
		return "audio"
	case strings.Contains(lower, "fprint") || strings.Contains(lower, "u2f") || strings.Contains(lower, "yubico") || strings.Contains(lower, "/pcsc/") || strings.Contains(lower, "opensc"):
		return "security-device"
	case strings.Contains(lower, "fwupd") || strings.Contains(lower, "tlp") || strings.Contains(lower, "upower"):
		return "power-firmware"
	case strings.Contains(lower, "keyd") || strings.Contains(lower, "kanata") || strings.Contains(lower, "input-remapper") || strings.Contains(lower, "solaar") || strings.Contains(lower, "xremap"):
		return "input-device"
	default:
		return "other"
	}
}

func hardwareDetails(path, content string) map[string]string {
	details := map[string]string{"category": hardwareCategory(path)}
	switch hardwareCategory(path) {
	case "printer":
		mergeDetails(details, cupsDetails(path, content))
	case "bluetooth":
		mergeDetails(details, bluetoothDetails(path, content))
	case "scanner":
		mergeDetails(details, saneDetails(path, content))
	case "audio":
		details["tool"] = audioTool(path)
		mergeDetails(details, genericHardwareConfigDetails(content))
	case "security-device":
		details["tool"] = securityDeviceTool(path)
		mergeDetails(details, securityDeviceDetails(path, content))
	case "power-firmware":
		details["tool"] = powerFirmwareTool(path)
		mergeDetails(details, genericHardwareConfigDetails(content))
	case "input-device":
		details["tool"] = inputDeviceTool(path)
		mergeDetails(details, genericHardwareConfigDetails(content))
	}
	return emptyNil(details)
}

func cupsDetails(path, content string) map[string]string {
	details := map[string]string{"tool": "cups"}
	if strings.HasSuffix(path, ".ppd") {
		details["ppd"] = "present"
		return details
	}
	printers, classes, defaults := 0, 0, 0
	schemes := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(line, "<Printer "):
			printers++
		case strings.HasPrefix(line, "<Class "):
			classes++
		case strings.HasPrefix(lower, "defaultprinter ") || strings.HasPrefix(lower, "default "):
			defaults++
		case strings.HasPrefix(lower, "deviceuri "):
			if scheme := uriScheme(strings.TrimSpace(line[len("DeviceURI "):])); scheme != "" {
				schemes[scheme] = true
			}
		}
	}
	setPositiveDetail(details, "printers", printers)
	setPositiveDetail(details, "classes", classes)
	setPositiveDetail(details, "defaults", defaults)
	if len(schemes) > 0 {
		details["device-uri-schemes"] = strings.Join(sortedKeys(schemes), ",")
	}
	return details
}

func bluetoothDetails(path, content string) map[string]string {
	details := map[string]string{"tool": "bluez"}
	if strings.Contains(path, "/var/lib/bluetooth/") && strings.HasSuffix(path, "/info") {
		details["paired-device"] = "present"
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "trusted", "paired", "blocked", "discoverabletimeout", "pairabletimeout":
			setDetail(details, strings.ToLower(key), value)
		case "class":
			details["device-class"] = "present"
		}
	}
	return details
}

func saneDetails(path, content string) map[string]string {
	details := map[string]string{"tool": "sane"}
	if strings.HasSuffix(path, "/dll.conf") {
		backends := 0
		netBackend := false
		sc := bufio.NewScanner(strings.NewReader(content))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			backends++
			if line == "net" {
				netBackend = true
			}
		}
		setPositiveDetail(details, "enabled-backends", backends)
		if netBackend {
			details["network-backend"] = "present"
		}
		return details
	}
	mergeDetails(details, genericHardwareConfigDetails(content))
	return details
}

func securityDeviceDetails(path, content string) map[string]string {
	details := map[string]string{}
	if strings.Contains(strings.ToLower(path), "u2f") {
		mappings := countNonCommentLines(content)
		setPositiveDetail(details, "mappings", mappings)
		details["manual-enrollment"] = "recommended"
		return details
	}
	if strings.Contains(strings.ToLower(path), "fprint") {
		details["manual-enrollment"] = "required"
	}
	mergeDetails(details, genericHardwareConfigDetails(content))
	return details
}

func genericHardwareConfigDetails(content string) map[string]string {
	details := map[string]string{}
	sections := 0
	settings := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripInlineComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections++
			continue
		}
		if strings.Contains(line, "=") || strings.Contains(line, ":") {
			settings++
		}
	}
	setPositiveDetail(details, "sections", sections)
	setPositiveDetail(details, "settings", settings)
	return emptyNil(details)
}

func audioTool(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "pipewire"):
		return "pipewire"
	case strings.Contains(lower, "/pulse/"):
		return "pulseaudio"
	case strings.Contains(lower, "asound"):
		return "alsa"
	default:
		return "audio"
	}
}

func securityDeviceTool(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "fprint"):
		return "fprintd"
	case strings.Contains(lower, "u2f"):
		return "u2f"
	case strings.Contains(lower, "yubico"):
		return "yubico"
	case strings.Contains(lower, "pcsc"):
		return "pcsc"
	case strings.Contains(lower, "opensc"):
		return "opensc"
	default:
		return "security-device"
	}
}

func powerFirmwareTool(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "fwupd"):
		return "fwupd"
	case strings.Contains(lower, "tlp"):
		return "tlp"
	case strings.Contains(lower, "upower"):
		return "upower"
	default:
		return "power"
	}
}

func inputDeviceTool(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "keyd"):
		return "keyd"
	case strings.Contains(lower, "kanata"):
		return "kanata"
	case strings.Contains(lower, "input-remapper"):
		return "input-remapper"
	case strings.Contains(lower, "solaar"):
		return "solaar"
	case strings.Contains(lower, "xremap"):
		return "xremap"
	default:
		return "input-device"
	}
}

func uriScheme(value string) string {
	if before, _, ok := strings.Cut(value, ":"); ok && before != "" {
		return strings.ToLower(before)
	}
	return ""
}

func countNonCommentLines(content string) int {
	count := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}
