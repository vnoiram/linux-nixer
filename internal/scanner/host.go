package scanner

import (
	"bufio"
	"bytes"
	"context"
	"sort"
	"strconv"
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
	groupsByGID, groupsByUser := readGroups(opts.Root)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		u := model.User{Name: parts[0], UID: parts[2], GID: parts[3], Home: parts[5], Shell: parts[6]}
		u.Groups = userGroups(u, groupsByGID, groupsByUser)
		u.System = isSystemUser(u)
		report.Users = append(report.Users, u)
	}
	return sc.Err()
}

func readGroups(root string) (map[string]string, map[string][]string) {
	b, ok := safeReadFile(root, rootPath(root, "/etc/group"))
	if !ok {
		return nil, nil
	}
	byGID := map[string]string{}
	byUser := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		gid := parts[2]
		byGID[gid] = name
		for _, member := range strings.Split(parts[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			byUser[member] = append(byUser[member], name)
		}
	}
	return byGID, byUser
}

func userGroups(user model.User, groupsByGID map[string]string, groupsByUser map[string][]string) []string {
	seen := map[string]bool{}
	var groups []string
	add := func(group string) {
		if group == "" || seen[group] {
			return
		}
		seen[group] = true
		groups = append(groups, group)
	}
	add(groupsByGID[user.GID])
	for _, group := range groupsByUser[user.Name] {
		add(group)
	}
	sort.Strings(groups)
	return groups
}

func isSystemUser(user model.User) bool {
	if user.Name == "root" {
		return false
	}
	if uid, err := strconv.Atoi(user.UID); err == nil && uid < 1000 {
		return true
	}
	shell := strings.TrimSpace(user.Shell)
	if strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
		return true
	}
	return !strings.HasPrefix(user.Home, "/home/")
}
