package scanner

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type DevOpsConfigScanner struct{}

func (DevOpsConfigScanner) Name() string { return "devops-config" }

func (DevOpsConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	for _, pattern := range []string{
		"/home/*/.kube/config",
		"/home/*/.docker/config.json",
		"/home/*/.config/helm/repositories.yaml",
		"/home/*/.terraformrc",
		"/home/*/.aws/config",
		"/home/*/.config/gcloud/configurations/*",
		"/home/*/.azure/config",
	} {
		for _, path := range glob(opts.Root, pattern) {
			display := displayPath(opts.Root, path)
			decision := model.DecisionMigrationNote
			secretRisk := hasAnySuffix(path, ".json", "config")
			if strings.Contains(display, ".aws/config") {
				decision = model.DecisionCandidate
				secretRisk = false
			}
			report.Items = append(report.Items, model.Item{
				Kind:     "devops-config",
				Name:     filepath.Base(path),
				Path:     display,
				Decision: decision,
				Reason:   devOpsConfigReason(display),
			})
			if secretRisk {
				report.Warnings = append(report.Warnings, model.Warning{
					Source:  "devops-config",
					Message: "secret-risk config detected: " + display,
				})
			}
		}
	}
	return nil
}

func devOpsConfigReason(path string) string {
	switch {
	case strings.Contains(path, "/.kube/"):
		return "kubernetes configuration may contain credentials"
	case strings.Contains(path, "/.docker/"):
		return "docker client configuration may contain credentials"
	case strings.Contains(path, "/helm/"):
		return "helm repository configuration may contain credentials"
	case strings.Contains(path, ".terraformrc"):
		return "terraform CLI configuration may contain credentials"
	case strings.Contains(path, "/.aws/"):
		return "aws CLI configuration"
	case strings.Contains(path, "/gcloud/"):
		return "gcloud configuration may contain credentials"
	case strings.Contains(path, "/.azure/"):
		return "azure CLI configuration may contain credentials"
	default:
		return "credentials are excluded by default"
	}
}
