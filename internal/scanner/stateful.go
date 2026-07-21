package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type StatefulDataScanner struct{}

func (StatefulDataScanner) Name() string { return "stateful-data" }

func (StatefulDataScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	for _, target := range statefulTargets() {
		for _, path := range glob(opts.Root, target.patterns...) {
			addStatefulFinding(opts, report, path, target.reason)
		}
	}
	return nil
}

type statefulTarget struct {
	reason   string
	patterns []string
}

func statefulTargets() []statefulTarget {
	return []statefulTarget{
		{reason: "postgresql data directory", patterns: []string{"/var/lib/postgresql"}},
		{reason: "mysql or mariadb data directory", patterns: []string{"/var/lib/mysql"}},
		{reason: "mongodb data directory", patterns: []string{"/var/lib/mongodb"}},
		{reason: "redis data directory", patterns: []string{"/var/lib/redis"}},
		{reason: "rabbitmq data directory", patterns: []string{"/var/lib/rabbitmq"}},
		{reason: "elasticsearch data directory", patterns: []string{"/var/lib/elasticsearch"}},
		{reason: "opensearch data directory", patterns: []string{"/var/lib/opensearch"}},
		{reason: "prometheus time-series database", patterns: []string{"/var/lib/prometheus"}},
		{reason: "grafana data directory", patterns: []string{"/var/lib/grafana"}},
		{reason: "influxdb data directory", patterns: []string{"/var/lib/influxdb", "/var/lib/influxdb2"}},
		{reason: "container runtime state", patterns: []string{"/var/lib/docker", "/var/lib/containers"}},
		{reason: "etcd cluster data", patterns: []string{"/var/lib/etcd"}},
		{reason: "libvirt virtual machine images", patterns: []string{"/var/lib/libvirt/images"}},
		{reason: "application data directory under /srv", patterns: []string{"/srv/*/data", "/srv/*/storage", "/srv/*/uploads"}},
	}
}

func addStatefulFinding(opts Options, report *model.ScanReport, path string, reason string) {
	display := displayPath(opts.Root, path)
	if shouldExclude(display, opts.Excludes) {
		return
	}
	info, ok := safeStat(opts.Root, path)
	if !ok {
		return
	}
	finding := model.FileFinding{
		Path:     display,
		Type:     statefulFindingType(info),
		Mode:     info.Mode().String(),
		Size:     statefulFindingSize(info),
		Category: "stateful-data",
		Reason:   filesystemReason(display, reason),
		Decision: model.DecisionMigrationNote,
	}
	appendStatefulFindingUnique(report, finding)
}

func statefulFindingType(info os.FileInfo) string {
	if info.IsDir() {
		return "directory"
	}
	return "file"
}

func statefulFindingSize(info os.FileInfo) int64 {
	if info.IsDir() {
		return 0
	}
	return info.Size()
}

func statefulDataReason(path string) string {
	for _, target := range statefulTargets() {
		for _, pattern := range target.patterns {
			if statefulPatternMatches(path, pattern) {
				return filesystemReason(path, target.reason)
			}
		}
	}
	return filesystemReason(path, "stateful data requires manual backup or migration")
}

func statefulPatternMatches(path string, pattern string) bool {
	if strings.Contains(pattern, "*") {
		prefix, suffix, _ := strings.Cut(pattern, "*")
		return strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")) && strings.HasSuffix(path, strings.TrimPrefix(suffix, "/"))
	}
	return path == pattern || strings.HasPrefix(path, pattern+"/")
}

func normalizeStatefulPath(path string) string {
	for _, target := range statefulTargets() {
		for _, pattern := range target.patterns {
			if !strings.Contains(pattern, "*") && (path == pattern || strings.HasPrefix(path, pattern+"/")) {
				return pattern
			}
		}
	}
	return filepath.Clean(path)
}
