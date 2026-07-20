package review

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
)

func TestApplyConfirmsSafeMappedPackages(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}},
			{Manager: "apt", Name: "unknown"},
		},
	}
	got := Apply(report, Options{AutoSafe: true})
	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("mapped package decision=%q", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("unknown package decision=%q", got.Packages[1].Decision)
	}
}

func TestApplyAutoSafePromotesCandidateMappedPackages(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Decision: model.DecisionCandidate},
			{Manager: "apt", Name: "vim", NixNames: []string{"vim"}, Decision: model.DecisionTODO},
		},
	}

	got := Apply(report, Options{AutoSafe: true})

	if got.Packages[0].Decision != model.DecisionConfirmed {
		t.Fatalf("candidate mapped package decision=%q, want confirmed", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionTODO {
		t.Fatalf("todo mapped package decision=%q, want todo", got.Packages[1].Decision)
	}
}

func TestApplyExcludesPathPrefixAndKeepsSecretsAsMigrationNotes(t *testing.T) {
	report := model.ScanReport{
		FilesystemDiff: []model.FileFinding{
			{Path: "/tmp/tool", Category: "script"},
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true},
		},
	}
	got := Apply(report, Options{ExcludePathPrefixes: []string{"/tmp"}})
	if got.FilesystemDiff[0].Decision != model.DecisionExcluded {
		t.Fatalf("excluded path decision=%q", got.FilesystemDiff[0].Decision)
	}
	if got.FilesystemDiff[1].Decision != model.DecisionMigrationNote {
		t.Fatalf("secret decision=%q", got.FilesystemDiff[1].Decision)
	}
}

func TestInteractiveAppliesChoices(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl"},
			{Manager: "apt", Name: "git"},
			{Manager: "apt", Name: "vim"},
			{Manager: "apt", Name: "tmux"},
			{Manager: "apt", Name: "jq"},
		},
	}
	in := strings.NewReader("c\nx\nt\nm\ns\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	wants := []model.Decision{
		model.DecisionConfirmed,
		model.DecisionExcluded,
		model.DecisionTODO,
		model.DecisionMigrationNote,
		model.DecisionCandidate,
	}
	for i, want := range wants {
		if got.Packages[i].Decision != want {
			t.Fatalf("package %d decision=%q, want %q", i, got.Packages[i].Decision, want)
		}
	}
	if !strings.Contains(out.String(), "choose c=confirmed") {
		t.Fatalf("interactive prompt missing choices: %s", out.String())
	}
}

func TestInteractiveProtectsSecretAndStatefulData(t *testing.T) {
	report := model.ScanReport{
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Category: "stateful-data"},
		},
	}
	in := strings.NewReader("c\nc\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	if got.FilesystemDiff[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("secret decision=%q, want migration-note", got.FilesystemDiff[0].Decision)
	}
	if got.StatefulData[0].Decision != model.DecisionMigrationNote {
		t.Fatalf("stateful decision=%q, want migration-note", got.StatefulData[0].Decision)
	}
	if strings.Count(out.String(), "protected finding cannot be confirmed") != 2 {
		t.Fatalf("expected protected warning twice, got: %s", out.String())
	}
}

func TestInteractiveQuitKeepsRemainingDecisions(t *testing.T) {
	report := model.ScanReport{
		Packages: []model.Package{
			{Manager: "apt", Name: "curl"},
			{Manager: "apt", Name: "git"},
		},
	}
	in := strings.NewReader("q\n")
	var out bytes.Buffer

	got := Interactive(in, &out, report, Options{})

	if got.Packages[0].Decision != model.DecisionCandidate {
		t.Fatalf("first package decision=%q, want candidate", got.Packages[0].Decision)
	}
	if got.Packages[1].Decision != model.DecisionCandidate {
		t.Fatalf("second package decision=%q, want candidate", got.Packages[1].Decision)
	}
}

func TestSummarizeCountsDecisionsDomainsProtectedFindingsAndNixImpact(t *testing.T) {
	report := model.ScanReport{
		Users: []model.User{
			{Name: "root", Home: "/root", System: true},
			{Name: "alice", Home: "/home/alice", Shell: "/bin/zsh"},
		},
		Packages: []model.Package{
			{Manager: "apt", Name: "curl", NixNames: []string{"curl"}, Decision: model.DecisionConfirmed},
			{Manager: "apt", Name: "unknown", Decision: model.DecisionCandidate},
		},
		Languages: model.Languages{
			NPM: []model.Package{
				{Manager: "npm", Name: "typescript", NixNames: []string{"nodePackages.typescript"}, Decision: model.DecisionConfirmed},
			},
			Python: []model.PythonEnv{{
				Path: "/home/alice/.local/pipx/venvs/ruff",
				Kind: "pipx",
				Packages: []model.Package{
					{Manager: "pipx", Name: "ruff", NixNames: []string{"ruff"}, Decision: model.DecisionTODO},
				},
			}},
		},
		Containers: []model.Container{
			{Runtime: "docker", Name: "web", Decision: model.DecisionConfirmed},
			{Runtime: "podman", Name: "db", Decision: model.DecisionExcluded},
		},
		Services: []model.Service{
			{Manager: "systemd", Name: "custom.service", Decision: model.DecisionConfirmed},
		},
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true, Decision: model.DecisionMigrationNote},
		},
		StatefulData: []model.FileFinding{
			{Path: "/var/lib/postgresql/data", Category: "stateful-data", Decision: model.DecisionMigrationNote},
		},
		Items: []model.Item{
			{Kind: "shell-config", Path: "/home/alice/.zshrc", Decision: model.DecisionConfirmed},
			{Kind: "user-config", Path: "/home/alice/.gitconfig", Decision: model.DecisionConfirmed},
		},
	}

	got := Summarize(report)

	if got.Total != 11 {
		t.Fatalf("total=%d, want 11", got.Total)
	}
	if got.Pending != 2 {
		t.Fatalf("pending=%d, want 2", got.Pending)
	}
	if got.ProtectedFindings != 2 {
		t.Fatalf("protected=%d, want 2", got.ProtectedFindings)
	}
	if got.UnmappedPackages != 1 {
		t.Fatalf("unmapped=%d, want 1", got.UnmappedPackages)
	}
	if got.ManualMigrationNotes != 2 {
		t.Fatalf("manual migration notes=%d, want 2", got.ManualMigrationNotes)
	}
	if got.SecretOrProtectedFindings != 2 {
		t.Fatalf("secret/protected=%d, want 2", got.SecretOrProtectedFindings)
	}
	if got.Decisions[string(model.DecisionConfirmed)] != 6 {
		t.Fatalf("confirmed=%d, want 6", got.Decisions[string(model.DecisionConfirmed)])
	}
	if got.Decisions[string(model.DecisionCandidate)] != 1 {
		t.Fatalf("candidate=%d, want 1", got.Decisions[string(model.DecisionCandidate)])
	}
	if got.Decisions[string(model.DecisionTODO)] != 1 {
		t.Fatalf("todo=%d, want 1", got.Decisions[string(model.DecisionTODO)])
	}
	if got.Decisions[string(model.DecisionMigrationNote)] != 2 {
		t.Fatalf("migration-note=%d, want 2", got.Decisions[string(model.DecisionMigrationNote)])
	}
	if got.Decisions[string(model.DecisionExcluded)] != 1 {
		t.Fatalf("excluded=%d, want 1", got.Decisions[string(model.DecisionExcluded)])
	}
	if got.NixImpact.SystemPackages != 1 || got.NixImpact.HomePackages != 1 || got.NixImpact.Users != 1 {
		t.Fatalf("unexpected nix package/user impact: %+v", got.NixImpact)
	}
	if got.NixImpact.HostShellPrograms != 1 || got.NixImpact.HomePrograms != 2 {
		t.Fatalf("unexpected nix program impact: %+v", got.NixImpact)
	}
	if got.NixImpact.SystemdServices != 1 || got.NixImpact.ContainerRuntimeEnables != 1 || got.NixImpact.ConfirmedContainers != 1 {
		t.Fatalf("unexpected nix service/container impact: %+v", got.NixImpact)
	}
	if got.GeneratedCandidates != 9 {
		t.Fatalf("generated candidates=%d, want 9", got.GeneratedCandidates)
	}
	if got.Domains[0].Domain != "packages" || got.Domains[0].UnmappedPackages != 1 {
		t.Fatalf("package domain unmapped missing: %+v", got.Domains[0])
	}
}

func TestFormatSummaryMarkdownOmitsFindingDetails(t *testing.T) {
	report := model.ScanReport{
		FilesystemDiff: []model.FileFinding{
			{Path: "/home/alice/.ssh/id_ed25519", Category: "secret", SecretRisk: true, Decision: model.DecisionMigrationNote},
		},
	}

	got := FormatSummaryMarkdown(Summarize(report))

	for _, want := range []string{"# Review summary", "## Review focus", "Protected findings: 1", "Secret/stateful/protected findings: 1", "## Next actions", "filesystem-findings"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "id_ed25519") {
		t.Fatalf("summary leaked protected finding path:\n%s", got)
	}
}
