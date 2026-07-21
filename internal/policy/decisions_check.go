package policy

import (
	"fmt"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/model"
	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/validate"
)

// knownDecisionDomains are the domains review.allDecisions ever produces.
var knownDecisionDomains = map[string]bool{
	"package":            true,
	"git-source":         true,
	"container":          true,
	"service":            true,
	"filesystem-finding": true,
	"stateful-data":      true,
	"item":               true,
}

// CheckDecisions compares set against p's kind vocabulary
// (ConfirmKinds/ExcludeKinds/TODOKinds/MigrationNoteKinds) and warns about
// entries that are stale (their recorded decision disagrees with what the
// current policy would now produce for their kind) or unresolvable (an
// unknown domain, or a key that doesn't carry a recoverable kind). Only
// "container", "service", "git-source", and "item" entries carry a kind
// recoverable from decisions.json alone — decideFinding/applyDecisions
// (internal/review/review.go) uses the domain name itself as the kind for
// the first three, and itemDecisionKey embeds an item's Kind as the key's
// prefix before the first ":". "package" is gated by ConfirmManagers, not a
// kind list; "filesystem-finding"'s kind (FileFinding.Category) and
// "stateful-data" (never kind-gated at all) aren't recoverable from a
// decisions.json entry, so all three are intentionally left unchecked
// rather than guessed at. Never produces Errors — a stale or unresolvable
// entry doesn't break ApplyDecisions, it's purely a hygiene warning.
func CheckDecisions(set review.DecisionSet, p Policy) validate.Result {
	var warnings []validate.Issue
	checked := 0
	for _, e := range set.Entries {
		checked++
		path := e.Domain + ":" + e.Key
		if !knownDecisionDomains[e.Domain] {
			warnings = append(warnings, validate.Issue{Path: path, Message: fmt.Sprintf("unknown domain %q", e.Domain)})
			continue
		}
		kind, ok := decisionKind(e)
		if !ok {
			if e.Domain == "item" {
				warnings = append(warnings, validate.Issue{Path: path, Message: fmt.Sprintf("key %q does not match the expected kind:path format", e.Key)})
			}
			continue
		}
		expected, matched := expectedDecisionForKind(kind, p)
		if !matched {
			continue
		}
		if e.Decision != "" && e.Decision != expected {
			warnings = append(warnings, validate.Issue{
				Path:    path,
				Message: fmt.Sprintf("decision %q conflicts with current policy for kind %q, which would set %q", e.Decision, kind, expected),
			})
		}
	}
	return validate.Result{OK: true, Checked: checked, Warnings: warnings}
}

func decisionKind(e review.DecisionEntry) (string, bool) {
	switch e.Domain {
	case "container", "service", "git-source":
		return e.Domain, true
	case "item":
		kind, _, found := strings.Cut(e.Key, ":")
		if !found || kind == "" {
			return "", false
		}
		return kind, true
	default:
		return "", false
	}
}

func expectedDecisionForKind(kind string, p Policy) (model.Decision, bool) {
	switch {
	case contains(p.ConfirmKinds, kind):
		return model.DecisionConfirmed, true
	case contains(p.ExcludeKinds, kind):
		return model.DecisionExcluded, true
	case contains(p.TODOKinds, kind):
		return model.DecisionTODO, true
	case contains(p.MigrationNoteKinds, kind):
		return model.DecisionMigrationNote, true
	}
	return "", false
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
