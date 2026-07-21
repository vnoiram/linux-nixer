package review

import "github.com/vnoiram/linux-nixer/internal/model"

// ProgressEntry is one finding whose decision state changed between a
// previous DecisionSet snapshot and the current scan report.
type ProgressEntry struct {
	Domain           string         `json:"domain"`
	Key              string         `json:"key"`
	PreviousDecision model.Decision `json:"previousDecision,omitempty"`
	CurrentDecision  model.Decision `json:"currentDecision,omitempty"`
}

// Progress is a diff between a previously exported DecisionSet and the
// current scan report's decisions, for tracking migration progress across
// repeated scans of the same host.
type Progress struct {
	PreviousDecided int             `json:"previousDecided"`
	CurrentDecided  int             `json:"currentDecided"`
	StillPending    int             `json:"stillPending"`
	NewlyDecided    []ProgressEntry `json:"newlyDecided,omitempty"`
	Changed         []ProgressEntry `json:"changed,omitempty"`
	Regressed       []ProgressEntry `json:"regressed,omitempty"`
	Removed         []ProgressEntry `json:"removed,omitempty"`
}

// ComputeProgress compares report's current decisions against a previously
// exported DecisionSet. Every finding is categorized into exactly one of:
// NewlyDecided (decided now, unseen before), Changed (decided differently
// than before), Regressed (was decided before, still present but back to
// candidate/empty now), or Removed (was decided before, no longer present
// in report at all). Findings unchanged since previous produce no entry.
func ComputeProgress(report model.ScanReport, previous DecisionSet) Progress {
	current := allDecisions(report)

	currentByKey := map[string]map[string]model.Decision{}
	for _, e := range current {
		if currentByKey[e.Domain] == nil {
			currentByKey[e.Domain] = map[string]model.Decision{}
		}
		currentByKey[e.Domain][e.Key] = e.Decision
	}
	previousByKey := map[string]map[string]model.Decision{}
	for _, e := range previous.Entries {
		if previousByKey[e.Domain] == nil {
			previousByKey[e.Domain] = map[string]model.Decision{}
		}
		previousByKey[e.Domain][e.Key] = e.Decision
	}

	progress := Progress{PreviousDecided: len(previous.Entries)}

	for _, e := range current {
		if isPending(e.Decision) {
			progress.StillPending++
		}
		if !isDecided(e.Decision) {
			continue
		}
		progress.CurrentDecided++
		prevDecision, existedBefore := previousByKey[e.Domain][e.Key]
		switch {
		case !existedBefore:
			progress.NewlyDecided = append(progress.NewlyDecided, ProgressEntry{Domain: e.Domain, Key: e.Key, CurrentDecision: e.Decision})
		case prevDecision != e.Decision:
			progress.Changed = append(progress.Changed, ProgressEntry{Domain: e.Domain, Key: e.Key, PreviousDecision: prevDecision, CurrentDecision: e.Decision})
		}
	}

	for _, e := range previous.Entries {
		currentDecision, stillExists := currentByKey[e.Domain][e.Key]
		switch {
		case !stillExists:
			progress.Removed = append(progress.Removed, ProgressEntry{Domain: e.Domain, Key: e.Key, PreviousDecision: e.Decision})
		case !isDecided(currentDecision):
			progress.Regressed = append(progress.Regressed, ProgressEntry{Domain: e.Domain, Key: e.Key, PreviousDecision: e.Decision})
		}
	}

	return progress
}
