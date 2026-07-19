package validate

import (
	"fmt"
	"strings"
)

func FormatText(result Result) string {
	var b strings.Builder
	if result.OK {
		fmt.Fprintf(&b, "valid scan: checked %d findings\n", result.Checked)
	} else {
		fmt.Fprintf(&b, "invalid scan: %d errors, checked %d findings\n", len(result.Errors), result.Checked)
	}
	if len(result.Errors) > 0 {
		b.WriteString("\nErrors:\n")
		for _, issue := range result.Errors {
			fmt.Fprintf(&b, "- %s: %s\n", issue.Path, issue.Message)
		}
	}
	if len(result.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, issue := range result.Warnings {
			fmt.Fprintf(&b, "- %s: %s\n", issue.Path, issue.Message)
		}
	}
	return b.String()
}
