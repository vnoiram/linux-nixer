package policy

import (
	"fmt"
	"strings"

	"github.com/vnoiram/linux-nixer/internal/validate"
)

func FormatDecisionConflictsMarkdown(result validate.Result) string {
	var b strings.Builder
	b.WriteString("# Decision conflict report\n\n")
	fmt.Fprintf(&b, "- Checked decisions: %d\n", result.Checked)
	fmt.Fprintf(&b, "- Errors: %d\n", len(result.Errors))
	fmt.Fprintf(&b, "- Warnings: %d\n\n", len(result.Warnings))
	if len(result.Errors) == 0 && len(result.Warnings) == 0 {
		b.WriteString("No decision conflicts or stale entries were found.\n")
		return b.String()
	}
	if len(result.Errors) > 0 {
		b.WriteString("## Errors\n\n")
		for _, issue := range result.Errors {
			fmt.Fprintf(&b, "- `%s`: %s\n", issue.Path, issue.Message)
		}
		b.WriteString("\n")
	}
	if len(result.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, issue := range result.Warnings {
			fmt.Fprintf(&b, "- `%s`: %s\n", issue.Path, issue.Message)
		}
	}
	return b.String()
}
