package scanner

import (
	"bufio"
	"bytes"
	"context"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type HostScanner struct{}

func (HostScanner) Name() string { return "host" }

func (HostScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	if text, err := readText(ctx, opts, report, "host", "/etc/os-release"); err == nil {
		for _, line := range strings.Split(text, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.Trim(value, `"`)
			switch key {
			case "ID":
				report.Host.Distro = value
			case "VERSION_ID":
				report.Host.Release = value
			}
		}
	}
	if text, err := readText(ctx, opts, report, "host", "/etc/hostname"); err == nil {
		report.Host.Hostname = strings.TrimSpace(text)
	}
	if opts.Root == "/" && commandAvailable("uname") {
		if out, err := runCommand(ctx, opts.Root, "uname", "-r"); err == nil {
			report.Host.Kernel = strings.TrimSpace(out)
		}
	}
	return nil
}

type UserScanner struct{}

func (UserScanner) Name() string { return "users" }

func (UserScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	b, err := readFile(ctx, opts, report, "users", "/etc/passwd")
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		u := model.User{Name: parts[0], UID: parts[2], GID: parts[3], Home: parts[5], Shell: parts[6]}
		u.System = !strings.HasPrefix(u.Home, "/home/") && u.Name != "root"
		report.Users = append(report.Users, u)
	}
	return sc.Err()
}
