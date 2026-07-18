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
	if opts.Root != "/" || !commandAvailable(runtime) {
		return
	}
	out, err := runCommand(ctx, opts.Root, runtime, "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var row map[string]string
		if json.Unmarshal([]byte(sc.Text()), &row) != nil {
			continue
		}
		report.Containers = append(report.Containers, model.Container{
			Runtime:  runtime,
			Name:     row["Names"],
			Image:    row["Image"],
			Ports:    splitCSV(row["Ports"]),
			Decision: model.DecisionCandidate,
		})
	}
}

func scanComposeFiles(opts Options, report *model.ScanReport) {
	patterns := []string{"/home/*/**/compose.yaml", "/home/*/**/compose.yml", "/home/*/**/docker-compose.yml", "/srv/**/compose.yaml", "/srv/**/docker-compose.yml"}
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
