package review

import (
	"fmt"
	"sort"
	"strings"
)

func FormatDecisionsMarkdown(set DecisionSet) string {
	var b strings.Builder
	b.WriteString("# Review decisions\n\n")
	fmt.Fprintf(&b, "- Schema version: %s\n", set.SchemaVersion)
	fmt.Fprintf(&b, "- Exported decisions: %d\n\n", len(set.Entries))
	if len(set.Entries) == 0 {
		b.WriteString("No non-default decisions were exported.\n")
		return b.String()
	}
	byDecision := map[string][]DecisionEntry{}
	for _, entry := range set.Entries {
		decision := string(entry.Decision)
		if decision == "" {
			decision = "candidate"
		}
		byDecision[decision] = append(byDecision[decision], entry)
	}
	decisions := make([]string, 0, len(byDecision))
	for decision := range byDecision {
		decisions = append(decisions, decision)
	}
	sort.Strings(decisions)
	for _, decision := range decisions {
		entries := byDecision[decision]
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Domain == entries[j].Domain {
				return entries[i].Key < entries[j].Key
			}
			return entries[i].Domain < entries[j].Domain
		})
		fmt.Fprintf(&b, "## %s (%d)\n\n", decision, len(entries))
		for _, entry := range entries {
			fmt.Fprintf(&b, "- `%s:%s`\n", entry.Domain, entry.Key)
		}
		b.WriteString("\n")
	}
	return b.String()
}
