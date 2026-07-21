package policy

import (
	"testing"

	"github.com/vnoiram/linux-nixer/internal/model"
	"github.com/vnoiram/linux-nixer/internal/review"
)

func TestCheckDecisionsWarnsAboutStaleAndUnresolvableEntries(t *testing.T) {
	p := Policy{
		SchemaVersion: SchemaVersion,
		ConfirmKinds:  []string{"service"},
		ExcludeKinds:  []string{"desktop-config"},
	}
	set := review.DecisionSet{
		SchemaVersion: review.DecisionsSchemaVersion,
		Entries: []review.DecisionEntry{
			// Agrees with policy: no warning.
			{Domain: "service", Key: "systemd:app.service", Decision: model.DecisionConfirmed},
			{Domain: "container", Key: "docker:web", Decision: model.DecisionCandidate},
			{Domain: "git-source", Key: "/srv/app", Decision: model.DecisionCandidate},
			{Domain: "item", Key: "desktop-config:/home/x/.config/foo", Decision: model.DecisionExcluded},
			// Stale: policy now says "confirmed" for kind "service".
			{Domain: "service", Key: "systemd:legacy.service", Decision: model.DecisionExcluded},
			// Unresolvable: malformed item key (no ":").
			{Domain: "item", Key: "no-colon-here", Decision: model.DecisionConfirmed},
			// Unresolvable: unknown domain.
			{Domain: "typo-domain", Key: "whatever", Decision: model.DecisionConfirmed},
			// Out of scope for kind checking: never warned regardless of content.
			{Domain: "package", Key: "apt:curl", Decision: model.DecisionExcluded},
			{Domain: "filesystem-finding", Key: "/etc/secret", Decision: model.DecisionConfirmed},
			{Domain: "stateful-data", Key: "/var/lib/db", Decision: model.DecisionCandidate},
		},
	}

	result := CheckDecisions(set, p)

	if !result.OK {
		t.Fatalf("CheckDecisions should never produce Errors, got: %+v", result)
	}
	if result.Checked != len(set.Entries) {
		t.Fatalf("Checked=%d, want %d", result.Checked, len(set.Entries))
	}
	if len(result.Warnings) != 3 {
		t.Fatalf("expected 3 warnings, got %d: %+v", len(result.Warnings), result.Warnings)
	}

	messages := map[string]bool{}
	for _, w := range result.Warnings {
		messages[w.Path+": "+w.Message] = true
	}
	wantSubstrings := []string{
		`service:systemd:legacy.service: decision "excluded" conflicts with current policy for kind "service", which would set "confirmed"`,
		`item:no-colon-here: key "no-colon-here" does not match the expected kind:path format`,
		`typo-domain:whatever: unknown domain "typo-domain"`,
	}
	for _, want := range wantSubstrings {
		if !messages[want] {
			t.Fatalf("missing warning %q in %+v", want, result.Warnings)
		}
	}
}
