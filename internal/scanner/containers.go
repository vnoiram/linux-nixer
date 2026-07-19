package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type ContainerScanner struct{}

func (ContainerScanner) Name() string { return "containers" }

func (ContainerScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	for _, runtime := range []string{"docker", "podman"} {
		scanRuntime(ctx, opts, report, runtime)
	}
	scanComposeFiles(opts, report)
	return nil
}

func scanRuntime(ctx context.Context, opts Options, report *model.ScanReport, runtime string) {
	if opts.Root != "/" {
		return
	}
	if opts.Runner == nil && !commandAvailable(runtime) {
		return
	}
	out, err := runWithOptions(ctx, opts, runtime, "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		var row map[string]string
		if json.Unmarshal([]byte(sc.Text()), &row) != nil {
			continue
		}
		container := model.Container{
			Runtime:  runtime,
			Name:     row["Names"],
			Image:    row["Image"],
			Ports:    splitCSV(row["Ports"]),
			Decision: model.DecisionCandidate,
		}
		enrichContainerFromInspect(ctx, opts, runtime, &container)
		report.Containers = append(report.Containers, container)
	}
}

func enrichContainerFromInspect(ctx context.Context, opts Options, runtime string, container *model.Container) {
	if container.Name == "" {
		return
	}
	out, err := runWithOptions(ctx, opts, runtime, "inspect", container.Name)
	if err != nil {
		return
	}
	var rows []struct {
		RepoDigests []string
		Config      struct {
			Image string
			Env   []string
		}
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string
				HostPort string
			}
		}
		Mounts []struct {
			Type        string
			Source      string
			Destination string
		}
	}
	if json.Unmarshal(out, &rows) != nil || len(rows) == 0 {
		return
	}
	row := rows[0]
	if row.Config.Image != "" {
		container.Image = row.Config.Image
	}
	if len(row.RepoDigests) > 0 {
		container.Digest = row.RepoDigests[0]
	}
	if len(container.Ports) == 0 {
		container.Ports = inspectPorts(row.NetworkSettings.Ports)
	}
	container.Mounts = inspectMounts(row.Mounts)
	container.Env = inspectEnvKeys(row.Config.Env)
}

func scanComposeFiles(opts Options, report *model.ScanReport) {
	patterns := []string{
		"/home/*/**/compose.yaml",
		"/home/*/**/compose.yml",
		"/home/*/**/docker-compose.yml",
		"/home/*/**/docker-compose.yaml",
		"/srv/**/compose.yaml",
		"/srv/**/compose.yml",
		"/srv/**/docker-compose.yml",
		"/srv/**/docker-compose.yaml",
	}
	for _, path := range recursiveGlob(opts.Root, patterns...) {
		report.Containers = append(report.Containers, model.Container{Runtime: "compose", Compose: displayPath(opts.Root, path), Decision: model.DecisionCandidate})
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func inspectPorts(ports map[string][]struct {
	HostIP   string
	HostPort string
}) []string {
	var out []string
	for containerPort, bindings := range ports {
		if len(bindings) == 0 {
			out = append(out, containerPort)
			continue
		}
		for _, binding := range bindings {
			host := binding.HostPort
			if binding.HostIP != "" {
				host = binding.HostIP + ":" + host
			}
			out = append(out, host+"->"+containerPort)
		}
	}
	return out
}

func inspectMounts(mounts []struct {
	Type        string
	Source      string
	Destination string
}) []string {
	var out []string
	for _, mount := range mounts {
		if mount.Source == "" && mount.Destination == "" {
			continue
		}
		value := mount.Source + ":" + mount.Destination
		if mount.Type != "" {
			value = mount.Type + ":" + value
		}
		out = append(out, value)
	}
	return out
}

func inspectEnvKeys(env []string) map[string]string {
	out := map[string]string{}
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		key = strings.TrimSpace(key)
		if key != "" {
			out[key] = ""
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func recursiveGlob(root string, patterns ...string) []string {
	var out []string
	for _, pattern := range patterns {
		if !strings.Contains(pattern, "**") {
			out = append(out, glob(root, pattern)...)
			continue
		}
		prefix, suffix, _ := strings.Cut(pattern, "**")
		bases, _ := filepath.Glob(rootPath(root, prefix))
		for _, base := range bases {
			filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					if d != nil && d.IsDir() && shouldSkipDir(d.Name()) {
						return filepath.SkipDir
					}
					return nil
				}
				if strings.HasSuffix(path, strings.TrimPrefix(suffix, "/")) {
					out = append(out, path)
				}
				return nil
			})
		}
	}
	return out
}
