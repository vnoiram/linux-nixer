package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type DevOpsConfigScanner struct{}

func (DevOpsConfigScanner) Name() string { return "devops-config" }

func (DevOpsConfigScanner) Scan(ctx context.Context, opts Options, report *model.ScanReport) error {
	_ = ctx
	seen := map[string]bool{}
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
			if seen[path] {
				continue
			}
			seen[path] = true
			display := displayPath(opts.Root, path)
			decision := model.DecisionMigrationNote
			details := devOpsProviderDetails(display, readLocalDevOpsFile(path))
			_, hasSecretRefs := details["secret-refs"]
			secretRisk := hasSecretRefs
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
				Details:  details,
			})
			if secretRisk {
				report.Warnings = append(report.Warnings, model.Warning{
					Source:  "devops-config",
					Message: "secret-risk config detected: " + display,
				})
			}
		}
	}
	scanCICDConfigs(opts, report, seen)
	return nil
}

func scanCICDConfigs(opts Options, report *model.ScanReport, seen map[string]bool) {
	for _, path := range findCICDWorkflowFiles(opts.Root) {
		addCICDItem(opts, report, seen, path, cicdWorkflowReason(displayPath(opts.Root, path)))
	}
	for _, path := range findCICDScriptFiles(opts.Root) {
		addCICDItemWithDetails(opts, report, seen, path, "deploy or release script", cicdAutomationDetails(path, readLocalDevOpsFile(path)))
	}
	for _, path := range recursiveGlob(opts.Root,
		"/home/*/**/Makefile",
		"/home/*/**/makefile",
		"/home/*/**/justfile",
		"/home/*/**/Justfile",
		"/home/*/**/Taskfile.yml",
		"/home/*/**/Taskfile.yaml",
		"/srv/**/Makefile",
		"/srv/**/makefile",
		"/srv/**/justfile",
		"/srv/**/Justfile",
		"/srv/**/Taskfile.yml",
		"/srv/**/Taskfile.yaml",
		"/opt/**/Makefile",
		"/opt/**/makefile",
		"/opt/**/justfile",
		"/opt/**/Justfile",
		"/opt/**/Taskfile.yml",
		"/opt/**/Taskfile.yaml",
	) {
		details := cicdAutomationDetails(path, readLocalDevOpsFile(path))
		if details == nil {
			continue
		}
		addCICDItemWithDetails(opts, report, seen, path, "project automation targets", details)
	}
}

func findCICDWorkflowFiles(root string) []string {
	return findDevOpsFiles(root, func(path string) bool {
		display := filepath.ToSlash(path)
		base := filepath.Base(path)
		return (strings.Contains(display, "/.github/workflows/") && hasAnySuffix(path, ".yml", ".yaml")) ||
			strings.HasSuffix(display, "/.gitlab-ci.yml") ||
			base == "Jenkinsfile" ||
			strings.HasSuffix(display, "/.circleci/config.yml") ||
			strings.HasSuffix(display, "/.circleci/config.yaml") ||
			strings.HasSuffix(display, "/.drone.yml") ||
			strings.HasSuffix(display, "/.woodpecker.yml") ||
			strings.HasSuffix(display, "/buildkite/pipeline.yml") ||
			strings.HasSuffix(display, "/.buildkite/pipeline.yml") ||
			strings.HasSuffix(display, "/azure-pipelines.yml") ||
			strings.HasSuffix(display, "/bitbucket-pipelines.yml")
	})
}

func findCICDScriptFiles(root string) []string {
	return findDevOpsFiles(root, func(path string) bool {
		display := filepath.ToSlash(path)
		base := filepath.Base(path)
		return (strings.Contains(display, "/scripts/") || strings.Contains(display, "/bin/")) &&
			(strings.HasPrefix(base, "deploy") || strings.HasPrefix(base, "release"))
	})
}

func findDevOpsFiles(root string, match func(string) bool) []string {
	var out []string
	for _, pattern := range []string{"/home/*", "/srv", "/opt"} {
		for _, base := range glob(root, pattern) {
			filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if path != base && shouldSkipDir(d.Name()) {
						return filepath.SkipDir
					}
					return nil
				}
				if match(path) {
					out = append(out, path)
				}
				return nil
			})
		}
	}
	sort.Strings(out)
	return out
}

func addCICDItem(opts Options, report *model.ScanReport, seen map[string]bool, path, reason string) {
	addCICDItemWithDetails(opts, report, seen, path, reason, cicdConfigDetails(path, readLocalDevOpsFile(path)))
}

func addCICDItemWithDetails(opts Options, report *model.ScanReport, seen map[string]bool, path, reason string, details map[string]string) {
	if seen[path] {
		return
	}
	seen[path] = true
	report.Items = append(report.Items, model.Item{
		Kind:     "cicd-config",
		Name:     filepath.Base(path),
		Path:     displayPath(opts.Root, path),
		Decision: model.DecisionCandidate,
		Reason:   reason,
		Details:  details,
	})
}

func readLocalDevOpsFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func devOpsProviderDetails(path, content string) map[string]string {
	switch {
	case strings.Contains(path, "/.kube/"):
		return kubeConfigDetails(content)
	case strings.Contains(path, "/.docker/"):
		return dockerClientConfigDetails(content)
	case strings.Contains(path, "/helm/"):
		return helmRepoDetails(content)
	case strings.Contains(path, ".terraformrc"):
		return terraformConfigDetails(content)
	case strings.Contains(path, "/.aws/"):
		return awsConfigDetails(content)
	case strings.Contains(path, "/gcloud/"):
		return gcloudConfigDetails(content)
	case strings.Contains(path, "/.azure/"):
		return azureConfigDetails(content)
	default:
		return nil
	}
}

func kubeConfigDetails(content string) map[string]string {
	details := map[string]string{}
	contexts, clusters, users, secretRefs := 0, 0, 0, 0
	currentContext, namespace, execAuth, authProvider := false, false, false, false
	section := ""
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		if isSecretReference(line) {
			secretRefs++
		}
		switch line {
		case "contexts:":
			section = "contexts"
			continue
		case "clusters:":
			section = "clusters"
			continue
		case "users:":
			section = "users"
			continue
		}
		if isTopLevelYAMLKey(line) {
			section = ""
		}
		if strings.HasPrefix(line, "- name:") {
			switch section {
			case "contexts":
				contexts++
			case "clusters":
				clusters++
			case "users":
				users++
			}
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "current-context:"):
			currentContext = true
		case strings.HasPrefix(lower, "namespace:"):
			namespace = true
		case strings.HasPrefix(lower, "exec:"):
			execAuth = true
		case strings.HasPrefix(lower, "auth-provider:"):
			authProvider = true
		}
	}
	setPositiveDetail(details, "contexts", contexts)
	setPositiveDetail(details, "clusters", clusters)
	setPositiveDetail(details, "users", users)
	setPositiveDetail(details, "secret-refs", secretRefs)
	setPresentDetail(details, "current-context", currentContext)
	setPresentDetail(details, "namespace", namespace)
	setPresentDetail(details, "exec-auth", execAuth)
	setPresentDetail(details, "auth-provider", authProvider)
	return emptyDevOpsDetails(details)
}

func dockerClientConfigDetails(content string) map[string]string {
	details := map[string]string{}
	var cfg struct {
		Auths          map[string]json.RawMessage `json:"auths"`
		CredsStore     string                     `json:"credsStore"`
		CredHelpers    map[string]string          `json:"credHelpers"`
		CurrentContext string                     `json:"currentContext"`
		Plugins        map[string]json.RawMessage `json:"plugins"`
	}
	if json.Unmarshal([]byte(content), &cfg) == nil {
		setPositiveDetail(details, "registries", len(cfg.Auths))
		setPresentDetail(details, "credential-store", cfg.CredsStore != "")
		setPositiveDetail(details, "credential-helpers", len(cfg.CredHelpers))
		setPresentDetail(details, "current-context", cfg.CurrentContext != "")
		setPositiveDetail(details, "plugins", len(cfg.Plugins))
		setPositiveDetail(details, "secret-refs", dockerAuthSecretRefs(cfg.Auths))
	}
	if _, ok := details["secret-refs"]; !ok {
		setPositiveDetail(details, "secret-refs", countSecretReferences(content))
	}
	return emptyDevOpsDetails(details)
}

func dockerAuthSecretRefs(auths map[string]json.RawMessage) int {
	secretRefs := 0
	for _, raw := range auths {
		var auth struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		}
		if json.Unmarshal(raw, &auth) != nil {
			continue
		}
		if auth.Auth != "" || auth.IdentityToken != "" {
			secretRefs++
		}
	}
	return secretRefs
}

func helmRepoDetails(content string) map[string]string {
	details := map[string]string{}
	repos, secretRefs := 0, 0
	schemes := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		if isSecretReference(line) {
			secretRefs++
		}
		if strings.HasPrefix(line, "- name:") {
			repos++
		}
		if strings.HasPrefix(strings.ToLower(line), "url:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "url:"))
			if scheme := devOpsURIScheme(value); scheme != "" {
				schemes[scheme] = true
			}
		}
	}
	setPositiveDetail(details, "repositories", repos)
	setPositiveDetail(details, "secret-refs", secretRefs)
	if len(schemes) > 0 {
		details["repository-schemes"] = strings.Join(sortedDevOpsKeys(schemes), ",")
	}
	return emptyDevOpsDetails(details)
}

func terraformConfigDetails(content string) map[string]string {
	details := map[string]string{}
	hosts, secretRefs := 0, 0
	credentialHelper, pluginCache, providerInstallation := false, false, false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if isSecretReference(line) {
			secretRefs++
		}
		if strings.HasPrefix(lower, "credentials ") {
			hosts++
		}
		if strings.Contains(lower, "credentials_helper") {
			credentialHelper = true
		}
		if strings.Contains(lower, "plugin_cache_dir") {
			pluginCache = true
		}
		if strings.Contains(lower, "provider_installation") {
			providerInstallation = true
		}
	}
	setPositiveDetail(details, "credential-hosts", hosts)
	setPositiveDetail(details, "secret-refs", secretRefs)
	setPresentDetail(details, "credential-helper", credentialHelper)
	setPresentDetail(details, "plugin-cache", pluginCache)
	setPresentDetail(details, "provider-installation", providerInstallation)
	return emptyDevOpsDetails(details)
}

func awsConfigDetails(content string) map[string]string {
	details := map[string]string{}
	profiles, regions, sso, secretRefs := 0, 0, 0, 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			profiles++
		}
		if strings.HasPrefix(lower, "region") {
			regions++
		}
		if strings.HasPrefix(lower, "sso_") {
			sso++
		}
		if isSecretReference(line) {
			secretRefs++
		}
	}
	setPositiveDetail(details, "profiles", profiles)
	setPositiveDetail(details, "regions", regions)
	setPositiveDetail(details, "sso-settings", sso)
	setPositiveDetail(details, "secret-refs", secretRefs)
	return emptyDevOpsDetails(details)
}

func gcloudConfigDetails(content string) map[string]string {
	details := map[string]string{}
	sections, properties, secretRefs := 0, 0, 0
	project, account := false, false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections++
			continue
		}
		if strings.Contains(line, "=") {
			properties++
		}
		if strings.HasPrefix(lower, "project") {
			project = true
		}
		if strings.HasPrefix(lower, "account") {
			account = true
		}
		if isSecretReference(line) {
			secretRefs++
		}
	}
	setPositiveDetail(details, "sections", sections)
	setPositiveDetail(details, "properties", properties)
	setPositiveDetail(details, "secret-refs", secretRefs)
	setPresentDetail(details, "project", project)
	setPresentDetail(details, "account", account)
	return emptyDevOpsDetails(details)
}

func azureConfigDetails(content string) map[string]string {
	details := map[string]string{}
	sections, settings, secretRefs := 0, 0, 0
	cloud, subscription, tenant := false, false, false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections++
			if strings.Contains(lower, "cloud") {
				cloud = true
			}
			continue
		}
		if strings.Contains(line, "=") {
			settings++
		}
		if strings.HasPrefix(lower, "cloud") {
			cloud = true
		}
		if strings.Contains(lower, "subscription") {
			subscription = true
		}
		if strings.Contains(lower, "tenant") {
			tenant = true
		}
		if isSecretReference(line) {
			secretRefs++
		}
	}
	setPositiveDetail(details, "sections", sections)
	setPositiveDetail(details, "settings", settings)
	setPositiveDetail(details, "secret-refs", secretRefs)
	setPresentDetail(details, "cloud", cloud)
	setPresentDetail(details, "subscription", subscription)
	setPresentDetail(details, "tenant", tenant)
	return emptyDevOpsDetails(details)
}

func cicdWorkflowReason(path string) string {
	switch {
	case strings.Contains(path, "/.github/workflows/"):
		return "github actions workflow"
	case strings.HasSuffix(path, "/.gitlab-ci.yml"):
		return "gitlab ci pipeline"
	case strings.HasSuffix(path, "/Jenkinsfile"):
		return "jenkins pipeline"
	case strings.Contains(path, "/.circleci/"):
		return "circleci pipeline"
	case strings.HasSuffix(path, "/.drone.yml"):
		return "drone ci pipeline"
	case strings.HasSuffix(path, "/.woodpecker.yml"):
		return "woodpecker ci pipeline"
	case strings.Contains(path, "/buildkite/") || strings.Contains(path, "/.buildkite/"):
		return "buildkite pipeline"
	case strings.HasSuffix(path, "/azure-pipelines.yml"):
		return "azure pipelines workflow"
	case strings.HasSuffix(path, "/bitbucket-pipelines.yml"):
		return "bitbucket pipelines workflow"
	default:
		return "ci/cd configuration"
	}
}

func cicdConfigDetails(path, content string) map[string]string {
	if content == "" {
		return nil
	}
	if strings.HasSuffix(path, "/Jenkinsfile") {
		return jenkinsDetails(content)
	}
	details := map[string]string{}
	jobs, stages, uses, services, cacheRefs, secretRefs := 0, 0, 0, 0, 0, 0
	triggers := map[string]bool{}
	inGitHubOn := false
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(stripDevOpsComment(sc.Text()))
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if isSecretReference(line) {
			secretRefs++
		}
		if strings.HasPrefix(line, "on:") {
			inGitHubOn = true
			addInlineWorkflowTriggers(triggers, strings.TrimSpace(strings.TrimPrefix(line, "on:")))
			continue
		}
		if inGitHubOn {
			if strings.HasPrefix(line, "jobs:") || isTopLevelYAMLKey(line) {
				inGitHubOn = false
			} else {
				key := yamlKey(line)
				if key != "" {
					triggers[key] = true
				}
			}
		}
		switch {
		case strings.HasPrefix(line, "pull_request:"):
			triggers["pull_request"] = true
		case strings.HasPrefix(line, "push:"):
			triggers["push"] = true
		case strings.HasPrefix(line, "workflow_dispatch:"):
			triggers["workflow_dispatch"] = true
		case strings.HasPrefix(line, "- uses:") || strings.HasPrefix(line, "uses:"):
			uses++
		case strings.HasPrefix(line, "services:"):
			services++
		case strings.Contains(lower, "cache"):
			cacheRefs++
		case strings.HasPrefix(line, "stage:") || strings.HasPrefix(line, "stages:") || strings.HasPrefix(line, "- stage:"):
			stages++
		}
		if looksLikeCICDJob(line, path) {
			jobs++
		}
	}
	setPositiveDetail(details, "jobs", jobs)
	setPositiveDetail(details, "stages", stages)
	setPositiveDetail(details, "uses", uses)
	setPositiveDetail(details, "services", services)
	setPositiveDetail(details, "cache-refs", cacheRefs)
	setPositiveDetail(details, "secret-refs", secretRefs)
	if len(triggers) > 0 {
		details["triggers"] = strings.Join(sortedDevOpsKeys(triggers), ",")
	}
	return emptyDevOpsDetails(details)
}

func jenkinsDetails(content string) map[string]string {
	details := map[string]string{}
	stages := strings.Count(content, "stage(")
	agents := strings.Count(content, "agent ")
	secretRefs := countSecretReferences(content)
	setPositiveDetail(details, "stages", stages)
	setPositiveDetail(details, "agents", agents)
	setPositiveDetail(details, "secret-refs", secretRefs)
	if strings.Contains(content, "pipeline {") {
		details["syntax"] = "declarative"
	}
	return emptyDevOpsDetails(details)
}

func cicdAutomationDetails(path, content string) map[string]string {
	if content == "" {
		return nil
	}
	details := map[string]string{}
	targets := map[string]bool{}
	shebang := ""
	secretRefs := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#!") && shebang == "" {
			shebang = strings.TrimPrefix(line, "#!")
		}
		if isSecretReference(line) {
			secretRefs++
		}
		lower := strings.ToLower(line)
		for _, keyword := range []string{"deploy", "release", "publish", "build", "test"} {
			if strings.Contains(lower, keyword) {
				targets[keyword] = true
			}
		}
		if target := automationTarget(path, line); target != "" {
			targets[target] = true
		}
	}
	if len(targets) == 0 {
		return nil
	}
	if shebang != "" {
		details["shebang"] = shebang
	}
	details["targets"] = strings.Join(sortedDevOpsKeys(targets), ",")
	setPositiveDetail(details, "secret-refs", secretRefs)
	return emptyDevOpsDetails(details)
}

func automationTarget(path, line string) string {
	trimmed := strings.TrimSpace(line)
	lowerName := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(lowerName, "makefile"):
		if strings.HasPrefix(trimmed, "\t") || strings.HasPrefix(trimmed, ".") {
			return ""
		}
		target, _, ok := strings.Cut(trimmed, ":")
		if ok && target != "" && !strings.ContainsAny(target, " \t") {
			return target
		}
	case strings.Contains(lowerName, "justfile"):
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "@") {
			return ""
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && strings.HasSuffix(fields[0], ":") {
			return strings.TrimSuffix(fields[0], ":")
		}
	case strings.HasPrefix(lowerName, "taskfile."):
		key := yamlKey(trimmed)
		if key != "" && (strings.Contains(strings.ToLower(key), "deploy") || strings.Contains(strings.ToLower(key), "release")) {
			return key
		}
	}
	return ""
}

func looksLikeCICDJob(line, path string) bool {
	if !strings.HasSuffix(line, ":") {
		return false
	}
	key := strings.TrimSuffix(line, ":")
	if key == "" || strings.HasPrefix(key, "-") || strings.Contains(key, " ") {
		return false
	}
	ignored := map[string]bool{
		"on": true, "env": true, "jobs": true, "steps": true, "with": true, "run": true, "services": true, "stages": true, "variables": true,
	}
	if ignored[key] {
		return false
	}
	return strings.Contains(path, "/.github/workflows/") || strings.HasSuffix(path, "/.gitlab-ci.yml") || strings.Contains(path, "/.circleci/") || strings.Contains(path, "/.buildkite/") || strings.HasSuffix(path, "/.drone.yml") || strings.HasSuffix(path, "/.woodpecker.yml") || strings.HasSuffix(path, "/azure-pipelines.yml") || strings.HasSuffix(path, "/bitbucket-pipelines.yml")
}

func addInlineWorkflowTriggers(triggers map[string]bool, value string) {
	value = strings.Trim(value, "[] ")
	for _, part := range strings.Split(value, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			triggers[part] = true
		}
	}
}

func yamlKey(line string) string {
	key, _, ok := strings.Cut(line, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(key, "-"))
}

func isTopLevelYAMLKey(line string) bool {
	return !strings.HasPrefix(line, "-") && strings.HasSuffix(line, ":") && !strings.Contains(strings.TrimSuffix(line, ":"), " ")
}

func stripDevOpsComment(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		return before
	}
	return line
}

func isSecretReference(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "secrets.") ||
		strings.Contains(lower, "secret_") ||
		strings.Contains(lower, "_secret") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "apikey") ||
		strings.Contains(lower, "private_key")
}

func countSecretReferences(content string) int {
	count := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		if isSecretReference(sc.Text()) {
			count++
		}
	}
	return count
}

func setPositiveDetail(details map[string]string, key string, value int) {
	if value > 0 {
		details[key] = strconv.Itoa(value)
	}
}

func setPresentDetail(details map[string]string, key string, present bool) {
	if present {
		details[key] = "present"
	}
}

func devOpsURIScheme(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if before, _, ok := strings.Cut(value, ":"); ok && before != "" {
		return strings.ToLower(before)
	}
	return ""
}

func sortedDevOpsKeys(values map[string]bool) []string {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func emptyDevOpsDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	return details
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
