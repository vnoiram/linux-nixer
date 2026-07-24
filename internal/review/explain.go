package review

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
)

type ExplainOptions struct {
	ReviewOptions Options
	Imported      DecisionSet
}

type Explanation struct {
	Domain   string
	Key      string
	Decision model.Decision
	Reason   string
}

func Explain(report model.ScanReport, opts ExplainOptions) []Explanation {
	imported := map[string]map[string]model.Decision{}
	for _, e := range opts.Imported.Entries {
		if imported[e.Domain] == nil {
			imported[e.Domain] = map[string]model.Decision{}
		}
		imported[e.Domain][e.Key] = e.Decision
	}
	var out []Explanation
	add := func(domain, key string, decision model.Decision, reason string) {
		if key == "" {
			return
		}
		if d, ok := imported[domain][key]; ok {
			reason = fmt.Sprintf("imported decision %q matched before policy rules", d)
		}
		if decision == "" {
			decision = model.DecisionCandidate
		}
		out = append(out, Explanation{Domain: domain, Key: key, Decision: decision, Reason: reason})
	}
	for _, pkg := range allPackages(report) {
		add("package", packageDecisionKey(pkg), pkg.Decision, packageDecisionReason(pkg, opts.ReviewOptions))
	}
	for _, g := range report.GitSources {
		add("git-source", g.Path, g.Decision, findingDecisionReason("git-source", g.Path, g.Decision, false, opts.ReviewOptions))
	}
	for _, c := range report.Containers {
		key := containerDecisionKey(c)
		add("container", key, c.Decision, findingDecisionReason("container", key, c.Decision, false, opts.ReviewOptions))
	}
	for _, s := range report.Services {
		add("service", serviceDecisionKey(s), s.Decision, findingDecisionReason("service", s.Path, s.Decision, false, opts.ReviewOptions))
	}
	for _, f := range report.FilesystemDiff {
		add("filesystem-finding", f.Path, f.Decision, findingDecisionReason(f.Category, f.Path, f.Decision, f.SecretRisk, opts.ReviewOptions))
	}
	for _, f := range report.StatefulData {
		add("stateful-data", f.Path, f.Decision, "stateful data is always kept as a migration note")
	}
	for _, it := range report.Items {
		add("item", itemDecisionKey(it), it.Decision, findingDecisionReason(it.Kind, it.Path, it.Decision, false, opts.ReviewOptions))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Domain == out[j].Domain {
			return out[i].Key < out[j].Key
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

func FormatExplainMarkdown(items []Explanation) string {
	var b strings.Builder
	b.WriteString("# Policy explanation\n\n")
	if len(items) == 0 {
		b.WriteString("No review-managed findings were present.\n")
		return b.String()
	}
	currentDomain := ""
	for _, item := range items {
		if item.Domain != currentDomain {
			currentDomain = item.Domain
			fmt.Fprintf(&b, "## %s\n\n", currentDomain)
		}
		fmt.Fprintf(&b, "- `%s`: %s - %s\n", item.Key, item.Decision, item.Reason)
	}
	return b.String()
}

func packageDecisionReason(pkg model.Package, opts Options) string {
	switch {
	case pathExcluded(pkg.Source, opts.ExcludePathPrefixes):
		return "excluded by path prefix"
	case contains(opts.ConfirmManagers, pkg.Manager):
		return "confirmed by manager rule"
	case opts.AutoSafe && len(pkg.NixNames) > 0:
		return "confirmed by auto-safe package mapping"
	case pkg.Decision != "" && pkg.Decision != model.DecisionCandidate:
		return "preserved existing explicit decision"
	default:
		return "left as candidate for manual review"
	}
}

func findingDecisionReason(kind, path string, decision model.Decision, secretRisk bool, opts Options) string {
	switch {
	case secretRisk:
		return "protected secret-like finding forced to migration-note"
	case pathExcluded(path, opts.ExcludePathPrefixes):
		return "excluded by path prefix"
	case contains(opts.ConfirmKinds, kind):
		return "matched confirm-kind policy rule"
	case contains(opts.ExcludeKinds, kind):
		return "matched exclude-kind policy rule"
	case contains(opts.TODOKinds, kind):
		return "matched todo-kind policy rule"
	case contains(opts.MigrationNoteKinds, kind):
		return "matched migration-note-kind policy rule"
	case decision != "" && decision != model.DecisionCandidate:
		return "preserved existing explicit decision"
	default:
		return "left as candidate for manual review"
	}
}
