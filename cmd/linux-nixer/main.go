package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vnoiram/linux-nixer/internal/baseline"
	"github.com/vnoiram/linux-nixer/internal/doctor"
	"github.com/vnoiram/linux-nixer/internal/model"
	"github.com/vnoiram/linux-nixer/internal/policy"
	"github.com/vnoiram/linux-nixer/internal/render"
	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/scanner"
	"github.com/vnoiram/linux-nixer/internal/validate"
)

var version = "0.1.0-dev"
var commit = "unknown"
var date = "unknown"

type captureSessionMetadata struct {
	SchemaVersion string              `json:"schemaVersion"`
	Version       string              `json:"version"`
	Commit        string              `json:"commit"`
	Built         string              `json:"built"`
	StartedAt     string              `json:"startedAt"`
	FinishedAt    string              `json:"finishedAt"`
	Scan          captureScanMetadata `json:"scan"`
	Review        captureReviewMeta   `json:"review"`
	Artifacts     []string            `json:"artifacts"`
}

type captureScanMetadata struct {
	Root          string   `json:"root"`
	Sudo          bool     `json:"sudo"`
	Deep          bool     `json:"deep"`
	Baseline      string   `json:"baseline,omitempty"`
	PolicyPath    string   `json:"policyPath,omitempty"`
	Preset        string   `json:"preset,omitempty"`
	IncludePaths  []string `json:"includePaths,omitempty"`
	ExcludePaths  []string `json:"excludePaths,omitempty"`
	Plugins       []string `json:"plugins,omitempty"`
	PluginTimeout string   `json:"pluginTimeout"`
}

type captureReviewMeta struct {
	AutoSafe        bool   `json:"autoSafe"`
	FailOnPending   bool   `json:"failOnPending"`
	ImportDecisions string `json:"importDecisions,omitempty"`
	ExportDecisions string `json:"exportDecisions,omitempty"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}
	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout)
	case "capture":
		return runCapture(ctx, args[1:], stdout)
	case "rescan":
		return runRescan(ctx, args[1:], stdout)
	case "review":
		return runReview(args[1:], stdin, stdout)
	case "summary":
		return runSummary(args[1:], stdout)
	case "validate":
		return runValidate(args[1:], stdout)
	case "generate":
		return runGenerate(args[1:], stdout)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout)
	case "baseline":
		return runBaseline(ctx, args[1:], stdin, stdout)
	case "policy":
		return runPolicy(args[1:], stdout)
	case "plugin":
		return runPlugin(ctx, args[1:], stdout)
	case "guide":
		fmt.Fprint(stdout, migrationGuide)
		return nil
	case "version", "--version", "-v":
		if len(args) > 1 && args[1] == "--full" {
			fmt.Fprintf(stdout, "version=%s commit=%s built=%s\n", version, commit, date)
			return nil
		}
		fmt.Fprintln(stdout, version)
		return nil
	case "help":
		return commandHelp(stdout, args[1:])
	case "--help", "-h":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run `linux-nixer help` to list commands or `linux-nixer guide` for the migration workflow", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `linux-nixer converts Debian/Ubuntu environments into NixOS + Home Manager flakes.

Usage:
  linux-nixer scan --out scan.json [--preset NAME | --policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH]
  linux-nixer capture --out DIR [--preset NAME | --policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--fail-on-pending]
  linux-nixer rescan --out DIR --import-decisions decisions.json [--preset NAME | --policy policy.json] [--root /] [--compare-decisions decisions.json]
  linux-nixer review --scan scan.json --out reviewed.json [--policy policy.json] [--auto-safe] [--interactive] [--confirm-kind KIND] [--exclude-kind KIND]
  linux-nixer summary --scan reviewed.json [--json] [--fail-on-pending]
  linux-nixer validate --scan reviewed.json [--json] [--strict]
  linux-nixer generate --scan reviewed.json --out ./nix-config
  linux-nixer doctor --project ./nix-config [--vm] [--boot] [--timeout 15s] [--host generated]
  linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baseline.json
  linux-nixer baseline fetch --distro ubuntu --release 24.04 [--backend docker|podman] [--offline] [--out baselines/ubuntu-24.04.json]
  linux-nixer baseline import --distro ubuntu --release 24.04 --tar PATH [--out baselines/ubuntu-24.04.json]
  linux-nixer baseline list [--json]
  linux-nixer baseline check [--backend docker|podman] [--json] [--fail-on-drift]
  linux-nixer policy init --out linux-nixer-policy.json [--preset workstation|server|developer-machine|minimal-audit]
  linux-nixer policy diff --from workstation --to server [--json]
  linux-nixer plugin check --plugin ./my-scanner [--timeout 30s] [--json]
  linux-nixer guide
  linux-nixer help <command>
  linux-nixer version [--full]`)
}

func commandHelp(w io.Writer, topic []string) error {
	if len(topic) == 0 {
		usage(w)
		return nil
	}
	switch topic[0] {
	case "scan":
		fmt.Fprint(w, scanHelp)
	case "capture":
		fmt.Fprint(w, captureHelp)
	case "rescan":
		fmt.Fprint(w, rescanHelp)
	case "review":
		fmt.Fprint(w, reviewHelp)
	case "summary":
		fmt.Fprint(w, summaryHelp)
	case "validate":
		fmt.Fprint(w, validateHelp)
	case "generate":
		fmt.Fprint(w, generateHelp)
	case "doctor":
		fmt.Fprint(w, doctorHelp)
	case "baseline":
		if len(topic) == 1 || topic[1] == "create" {
			fmt.Fprint(w, baselineCreateHelp)
			return nil
		}
		if topic[1] == "fetch" {
			fmt.Fprint(w, baselineFetchHelp)
			return nil
		}
		if topic[1] == "import" {
			fmt.Fprint(w, baselineImportHelp)
			return nil
		}
		if topic[1] == "list" {
			fmt.Fprint(w, baselineListHelp)
			return nil
		}
		if topic[1] == "check" {
			fmt.Fprint(w, baselineCheckHelp)
			return nil
		}
		return fmt.Errorf("unknown help topic %q", "baseline "+topic[1])
	case "policy":
		if len(topic) == 1 || topic[1] == "init" {
			fmt.Fprint(w, policyInitHelp)
			return nil
		}
		if topic[1] == "diff" {
			fmt.Fprint(w, policyDiffHelp)
			return nil
		}
		return fmt.Errorf("unknown help topic %q", "policy "+topic[1])
	case "plugin":
		if len(topic) == 1 || topic[1] == "check" {
			fmt.Fprint(w, pluginCheckHelp)
			return nil
		}
		return fmt.Errorf("unknown help topic %q", "plugin "+topic[1])
	case "guide", "migration-guide":
		fmt.Fprint(w, migrationGuide)
	default:
		return fmt.Errorf("unknown help topic %q", topic[0])
	}
	return nil
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

const scanHelp = `linux-nixer scan
Scan a Debian/Ubuntu-like root filesystem and write scan JSON.

Usage:
  linux-nixer scan --out scan.json [--preset NAME | --policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--plugin PATH] [--plugin-timeout DURATION]

Examples:
  linux-nixer scan --out scan.json
  linux-nixer scan --preset developer-machine --out scan.json
  linux-nixer scan --sudo --deep --out scan.json
  linux-nixer scan --root /mnt/ubuntu --include /opt --baseline ubuntu:24.04 --out scan.json
  linux-nixer scan --plugin ./my-scanner --out scan.json

Flags:
  --out PATH               Write scan JSON to PATH.
  --preset NAME            Use a built-in policy preset directly: default, workstation, server, developer-machine, or minimal-audit. Mutually exclusive with --policy.
  --policy PATH            Load repeatable scan and review policy from PATH. Mutually exclusive with --preset.
  --root PATH              Scan PATH as the root filesystem. Defaults to /.
  --sudo                   Allow read-only sudo fallback for selected host files.
  --deep                   Scan broader filesystem paths for manual installs and config.
  --baseline ID            Compare filesystem findings against a baseline id or JSON path.
  --include PATH           Add a path to filesystem-diff scanning. Repeatable.
  --exclude PATH           Exclude a path prefix from scanning. Repeatable.
  --plugin PATH            Run an external scanner plugin executable. Repeatable. See "Plugin scanners" in DESIGN_AND_ROADMAP.md for the protocol. Plugins always run as the current user, never with --sudo elevation.
  --plugin-timeout DURATION  Timeout for each plugin scanner invocation. Defaults to 30s.

Policy:
  --preset picks a built-in policy.Template by name, for a one-shot run with no separate file to manage; --policy loads a custom policy JSON instead, e.g. from "policy init --preset NAME --out file.json" if you want to tweak a preset before running. Omitting both is the same as --preset default (root /, no --deep, auto-safe review). Policy include/exclude/plugin lists (whether from --preset or --policy) are merged with CLI list flags. Explicit CLI boolean and string flags override policy values.
`

const migrationGuide = `linux-nixer migration guide

Fast path:
  linux-nixer capture --out linux-nixer-output
  linux-nixer validate --scan linux-nixer-output/reviewed.json --strict
  linux-nixer summary --scan linux-nixer-output/reviewed.json --fail-on-pending
  linux-nixer doctor --project linux-nixer-output/nix-config

Review-first path:
  linux-nixer scan --out scan.json
  linux-nixer policy init --out linux-nixer-policy.json
  linux-nixer review --scan scan.json --out reviewed.json --policy linux-nixer-policy.json --interactive
  linux-nixer validate --scan reviewed.json --strict
  linux-nixer summary --scan reviewed.json
  linux-nixer generate --scan reviewed.json --out nix-config
  linux-nixer doctor --project nix-config

Repeatable sessions:
  linux-nixer review --scan scan.json --out reviewed.json --export-decisions decisions.json
  linux-nixer capture --out linux-nixer-output --import-decisions decisions.json --export-decisions decisions.json
  linux-nixer summary --scan linux-nixer-output/reviewed.json --compare-decisions decisions.json

Notes:
  Generated Nix only uses confirmed findings.
  Secret-risk and stateful findings stay as manual migration notes.
  Use "linux-nixer help <command>" for the exact flags supported by each command.
`

const captureHelp = `linux-nixer capture
Run scan, auto-safe review, summary, and Nix generation in one workflow.

Usage:
  linux-nixer capture --out DIR [--preset NAME | --policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--plugin PATH] [--plugin-timeout DURATION] [--auto-safe=false] [--fail-on-pending] [--import-decisions PATH] [--export-decisions PATH]

Examples:
  linux-nixer capture --out linux-nixer-output
  linux-nixer capture --preset developer-machine --out linux-nixer-output
  linux-nixer capture --sudo --deep --out linux-nixer-output
  linux-nixer capture --policy linux-nixer-policy.json --root /mnt/ubuntu --include /opt --out linux-nixer-output
  linux-nixer capture --import-decisions decisions.json --export-decisions decisions.json --out linux-nixer-output
  linux-nixer capture --plugin ./my-scanner --out linux-nixer-output

Artifacts:
  DIR/scan.json
  DIR/reviewed.json
  DIR/summary.md
  DIR/nix-config/

Flags:
  --out DIR                 Write capture artifacts under DIR.
  --preset NAME             Use a built-in policy preset directly: default, workstation, server, developer-machine, or minimal-audit. Mutually exclusive with --policy.
  --policy PATH             Load repeatable scan and review policy from PATH. Mutually exclusive with --preset.
  --root PATH               Scan PATH as the root filesystem. Defaults to /.
  --sudo                    Allow read-only sudo fallback for selected host files.
  --deep                    Scan broader filesystem paths for manual installs and config.
  --baseline ID             Compare filesystem findings against a baseline id or JSON path.
  --include PATH            Add a path to filesystem-diff scanning. Repeatable.
  --exclude PATH            Exclude a path prefix from scanning. Repeatable.
  --plugin PATH             Run an external scanner plugin executable. Repeatable. See "Plugin scanners" in DESIGN_AND_ROADMAP.md for the protocol. Plugins always run as the current user, never with --sudo elevation.
  --plugin-timeout DURATION Timeout for each plugin scanner invocation. Defaults to 30s.
  --auto-safe=false         Disable high-confidence automatic confirmations.
  --fail-on-pending         Return an error if candidate or todo findings remain.
  --import-decisions PATH   Seed decisions from a previously exported decisions JSON before review.
  --export-decisions PATH   Write the final decisions to a portable decisions JSON.

Policy:
  --preset picks a built-in policy.Template by name, for a one-shot run with no separate file to manage; --policy loads a custom policy JSON instead, e.g. from "policy init --preset NAME --out file.json" if you want to tweak a preset before running. Omitting both is the same as --preset default (root /, no --deep, auto-safe review) — running plain "capture --out DIR" with no other flags already does a reasonable one-shot scan. Policy scan and review defaults (from either source) are applied first. Explicit CLI boolean and string flags override policy values; CLI list flags are merged with policy lists.

Repeatable sessions:
  --export-decisions writes a host-independent record of every non-default decision, keyed by finding identity (e.g. "apt:curl", "systemd:app.service") rather than scan position. --import-decisions seeds a later scan (a re-scan of the same host, or a teammate's scan of a similar one) with those decisions before policy rules run, so previously reviewed findings don't need to be re-decided.
`

const rescanHelp = `linux-nixer rescan
Run scan, imported-decision review, and summary/progress output for a repeated migration session.

Usage:
  linux-nixer rescan --out DIR --import-decisions decisions.json [--preset NAME | --policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--plugin PATH] [--plugin-timeout DURATION] [--compare-decisions PATH]

Examples:
  linux-nixer rescan --out linux-nixer-rescan --import-decisions decisions.json
  linux-nixer rescan --root /mnt/ubuntu --out linux-nixer-rescan --import-decisions decisions.json --compare-decisions decisions.json

Artifacts:
  DIR/scan.json
  DIR/reviewed.json
  DIR/summary.md

Flags:
  --out DIR                 Write rescan artifacts under DIR.
  --import-decisions PATH   Seed decisions from a previously exported decisions JSON before review.
  --compare-decisions PATH  Compare reviewed output against a previous decisions JSON. Defaults to --import-decisions when omitted.
  --preset NAME             Use a built-in policy preset directly: default, workstation, server, developer-machine, or minimal-audit. Mutually exclusive with --policy.
  --policy PATH             Load repeatable scan and review policy from PATH. Mutually exclusive with --preset.
  --root PATH               Scan PATH as the root filesystem. Defaults to /.
  --sudo                    Allow read-only sudo fallback for selected host files.
  --deep                    Scan broader filesystem paths.
  --baseline ID             Compare filesystem findings against a baseline id or JSON path.
  --include PATH            Add a path to filesystem-diff scanning. Repeatable.
  --exclude PATH            Exclude a path prefix from scanning. Repeatable.
  --plugin PATH             Run an external scanner plugin executable. Repeatable.
  --plugin-timeout DURATION Timeout for each plugin scanner invocation. Defaults to 30s.
`

const reviewHelp = `linux-nixer review
Apply repeatable review decisions or run an interactive review over scan JSON.

Usage:
  linux-nixer review --scan scan.json --out reviewed.json [--policy policy.json] [--auto-safe] [--interactive] [--pending-only] [--confirm-kind KIND] [--exclude-kind KIND] [--todo-kind KIND] [--migration-note-kind KIND] [--confirm-manager MANAGER] [--exclude-path PATH] [--import-decisions PATH] [--export-decisions PATH]

Examples:
  linux-nixer review --scan scan.json --out reviewed.json --auto-safe
  linux-nixer review --scan scan.json --out reviewed.json --interactive
  linux-nixer review --scan scan.json --out reviewed.json --interactive --pending-only
  linux-nixer review --policy linux-nixer-policy.json --scan scan.json --out reviewed.json
  linux-nixer review --scan scan-a.json --out reviewed-a.json --confirm-kind service --export-decisions decisions.json
  linux-nixer review --scan scan-b.json --out reviewed-b.json --import-decisions decisions.json

Flags:
  --scan PATH                  Read input scan JSON.
  --out PATH                   Write reviewed scan JSON.
  --policy PATH                Load repeatable review policy from PATH.
  --auto-safe                  Confirm high-confidence safe findings.
  --interactive                Prompt for each finding with c/k/t/m/x/s/n/q choices, safe context notes, and per-section progress. n skips the rest of the current section.
  --pending-only               In interactive mode, only prompt for findings still at candidate; skip ones already resolved by policy or safety rules.
  --confirm-kind KIND          Mark findings of kind/category as confirmed. Repeatable.
  --exclude-kind KIND          Mark findings of kind/category as excluded. Repeatable.
  --todo-kind KIND             Mark findings of kind/category as todo. Repeatable.
  --migration-note-kind KIND   Mark findings of kind/category as migration-note. Repeatable.
  --confirm-manager MANAGER    Confirm packages from a package manager. Repeatable.
  --exclude-path PATH          Exclude findings with a path prefix. Repeatable.
  --import-decisions PATH      Seed decisions from a previously exported decisions JSON before policy rules run.
  --export-decisions PATH      Write the final decisions to a portable decisions JSON.

Policy:
  Policy decisions are applied first. Explicit CLI --auto-safe overrides policy autoSafe; CLI list flags are merged with policy lists.

Repeatable sessions:
  --export-decisions writes every non-default decision keyed by finding identity (e.g. "apt:curl", "systemd:app.service"), not scan position, so it stays meaningful across a re-scan or a teammate's scan of a similar host. --import-decisions seeds those decisions into a fresh scan before policy rules run, so imported (explicit, previously reviewed) decisions win over category-level policy defaults, and previously reviewed findings don't need to be re-decided.
`

const summaryHelp = `linux-nixer summary
Summarize reviewed scan decisions, review focus, and next actions for humans or automation.

Usage:
  linux-nixer summary --scan reviewed.json [--json] [--fail-on-pending] [--compare-decisions PATH]

Examples:
  linux-nixer summary --scan reviewed.json
  linux-nixer summary --scan reviewed.json --json
  linux-nixer summary --scan reviewed.json --fail-on-pending
  linux-nixer review --scan scan-a.json --out reviewed-a.json --export-decisions decisions-a.json
  linux-nixer summary --scan reviewed-b.json --compare-decisions decisions-a.json

Flags:
  --scan PATH                 Read reviewed scan JSON.
  --json                      Write machine-readable JSON summary.
  --fail-on-pending           Return an error if candidate or todo findings remain.
  --compare-decisions PATH    Compare against a previously exported decisions JSON (see review --export-decisions) and report what's newly decided, changed, regressed to pending, or no longer present — migration progress across repeated scans of the same host.
`

const validateHelp = `linux-nixer validate
Validate scan or reviewed scan JSON before using it for generation or CI gates, or check a decisions JSON for consistency with a policy's kind vocabulary.

Usage:
  linux-nixer validate --scan reviewed.json [--json] [--strict]
  linux-nixer validate --decisions decisions.json --policy policy.json [--json]

Examples:
  linux-nixer validate --scan reviewed.json
  linux-nixer validate --scan reviewed.json --json
  linux-nixer validate --scan reviewed.json --strict
  linux-nixer validate --decisions decisions.json --policy policy.json

Flags:
  --scan PATH        Read scan JSON.
  --decisions PATH   Check a decisions JSON (see --export-decisions) for stale or unresolvable entries against --policy. Combinable with --scan.
  --policy PATH      Policy JSON to check --decisions against. Required together with --decisions.
  --json             Write machine-readable JSON validation result.
  --strict           Reject unknown JSON fields in addition to semantic validation. Applies to --scan only.

The --decisions check compares each entry's kind (derived from its domain/key) against the policy's confirmKinds/excludeKinds/todoKinds/migrationNoteKinds and warns when the recorded decision disagrees with what the current policy would now produce — a sign the decision predates a later policy change. It also warns about entries with an unrecognized domain or a malformed key. Package, filesystem-finding, and stateful-data entries have no kind vocabulary to check against and are never flagged. These are warnings, not errors: a stale or unresolvable entry still works correctly when reapplied, since an explicit decision always wins over policy category rules.
`

const pluginCheckHelp = `linux-nixer plugin check
Invoke a scanner plugin once with a synthetic request and validate its JSON output before pointing a real scan/capture at it.

Usage:
  linux-nixer plugin check --plugin PATH [--timeout 30s] [--json]

Examples:
  linux-nixer plugin check --plugin ./my-scanner
  linux-nixer plugin check --plugin ./my-scanner --timeout 5s
  linux-nixer plugin check --plugin ./my-scanner --json

Flags:
  --plugin PATH   Path to the plugin executable to check.
  --timeout VALUE Timeout for the plugin invocation. Defaults to 30s.
  --json          Write machine-readable JSON validation result.

The plugin is run exactly once, the same way scan/capture would run it (see "Plugin scanners" in DESIGN_AND_ROADMAP.md), and its output is validated with the same structural checks as "linux-nixer validate".
`

const generateHelp = `linux-nixer generate
Render a conservative NixOS + Home Manager flake from reviewed scan JSON.

Usage:
  linux-nixer generate --scan reviewed.json --out ./nix-config

Examples:
  linux-nixer generate --scan reviewed.json --out nix-config

Flags:
  --scan PATH    Read reviewed scan JSON.
  --out DIR      Write generated flake project to DIR.
`

const doctorHelp = `linux-nixer doctor
Validate generated Nix files and optionally build or boot a NixOS VM.

Usage:
  linux-nixer doctor --project ./nix-config [--vm] [--boot] [--timeout 15s] [--host generated]

Examples:
  linux-nixer doctor --project nix-config
  linux-nixer doctor --project nix-config --vm --host generated
  linux-nixer doctor --project nix-config --vm --boot --timeout 30s

Flags:
  --project DIR      Generated flake project to check.
  --vm               Attempt NixOS VM build validation.
  --boot             Attempt to start the generated VM script.
  --timeout VALUE    VM boot validation timeout. Defaults to 15s.
  --host NAME        NixOS configuration name for VM validation.

Exit status:
  Always writes the full check result as JSON to stdout. Exits non-zero if any check failed, suitable for a CI gate.
`

const baselineCreateHelp = `linux-nixer baseline create
Create a baseline manifest for a distro rootfs so later scans can report only local filesystem differences.

Usage:
  linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baseline.json

Examples:
  linux-nixer baseline create --distro ubuntu --release 24.04 --root /mnt/base --out baselines/ubuntu-24.04.json
  linux-nixer scan --baseline ubuntu:24.04 --include /opt --out scan.json

Flags:
  --distro NAME      Distro name for the baseline id.
  --release VALUE    Distro release version for the baseline id.
  --root PATH        Rootfs path to manifest. Defaults to /.
  --out PATH         Write baseline JSON to PATH.
`

const baselineFetchHelp = `linux-nixer baseline fetch
Build a baseline manifest from the official Docker/Podman image for a distro release, without needing a local rootfs.

Usage:
  linux-nixer baseline fetch --distro ubuntu --release 24.04 [--backend docker|podman] [--offline] [--out PATH]

Examples:
  linux-nixer baseline fetch --distro ubuntu --release 24.04
  linux-nixer baseline fetch --distro debian --release 12 --out baselines/debian-12.json
  linux-nixer baseline fetch --distro ubuntu --release 24.04 --offline
  linux-nixer scan --baseline ubuntu:24.04 --include /opt --out scan.json

Flags:
  --distro NAME      Distro name; must be in the baseline catalog (see: linux-nixer baseline list).
  --release VALUE    Distro release version; must be in the baseline catalog for --distro.
  --backend NAME     Container backend: docker or podman. Auto-detected from PATH if omitted. Ignored with --offline.
  --offline          Use the manifest bundled into this binary instead of pulling a live image. No Docker/Podman or network access needed. Only works for distro/release pairs bundled offline (currently the whole catalog).
  --out PATH         Write baseline JSON to PATH. Defaults to baselines/<distro>-<release>.json.

Pulls the catalog's verified image for --distro/--release by its exact pinned digest (not the floating tag, so the fetched content can't silently drift as the tag gets rebuilt), exports its filesystem, and builds the manifest from real file contents — no hand-maintained package data. Run "linux-nixer baseline list" to see supported distro/release pairs before fetching. With --offline, skips the pull entirely and uses the pre-built manifest already bundled into this binary.
`

const baselineListHelp = `linux-nixer baseline list
List the curated distro/release pairs "baseline fetch" knows how to pull.

Usage:
  linux-nixer baseline list [--json]

Examples:
  linux-nixer baseline list
  linux-nixer baseline list --json
  linux-nixer baseline fetch --distro ubuntu --release 24.04

Flags:
  --json             Write machine-readable JSON (one object per catalog entry: distro, release, image, digest) instead of plain text.

This is a small, hand-verified catalog (see DESIGN_AND_ROADMAP.md's "Baseline catalog maintenance"), not every possible Docker Hub image — an unlisted distro/release is rejected by "baseline fetch" rather than guessed at. Every entry currently listed here also works fully offline via "baseline fetch --offline" (no Docker/Podman or network access needed), since its manifest is bundled directly into this binary.
`

const baselineCheckHelp = `linux-nixer baseline check
Check whether each catalog entry's pinned digest still matches what its tag currently resolves to.

Usage:
  linux-nixer baseline check [--backend docker|podman] [--json] [--fail-on-drift]

Examples:
  linux-nixer baseline check
  linux-nixer baseline check --json
  linux-nixer baseline check --fail-on-drift

Flags:
  --backend NAME     Container backend: docker or podman. Auto-detected from PATH if omitted.
  --json             Write machine-readable JSON (one object per catalog entry: distro, release, image, pinned/current digest, drifted, error) instead of plain text.
  --fail-on-drift    Exit non-zero if any entry has drifted from its pinned digest or could not be checked (network/backend failure). Default is report-only, exit 0.

Purely informational — this never modifies the catalog. A drifted entry (its tag now resolves to a different digest than the one pinned in internal/baseline/catalog.go) means the image was rebuilt upstream since the catalog was last verified; bumping the pinned digest is a deliberate, reviewed catalog change, not something this command does automatically. See DESIGN_AND_ROADMAP.md's "Baseline catalog maintenance" section.
`

const baselineImportHelp = `linux-nixer baseline import
Build a baseline manifest from an already-downloaded flat rootfs tar, without Docker/Podman or network access.

Usage:
  linux-nixer baseline import --distro ubuntu --release 24.04 --tar PATH [--out PATH]

Examples:
  linux-nixer baseline import --distro ubuntu --release 24.04 --tar ubuntu-base-24.04-base-amd64.tar.gz
  docker export web | linux-nixer baseline import --distro ubuntu --release 24.04 --tar -
  linux-nixer scan --baseline ubuntu:24.04 --include /opt --out scan.json

Flags:
  --distro NAME      Distro name for the baseline id.
  --release VALUE    Distro release version for the baseline id.
  --tar PATH         Path to a flat rootfs tar or tar.gz. Use - to read from stdin.
  --out PATH         Write baseline JSON to PATH. Defaults to baselines/<distro>-<release>.json.

--tar accepts only flat rootfs tars: an official distro base-rootfs tarball, or the output of ` + "`docker export <container>`" + `. A ` + "`docker save`" + ` image tar (multi-layer, with a manifest.json) is a different format and is not supported.
`

const policyInitHelp = `linux-nixer policy init
Write a reusable policy template for scan paths, baselines, and review decisions.

Usage:
  linux-nixer policy init --out linux-nixer-policy.json [--preset workstation|server|developer-machine|minimal-audit]

Examples:
  linux-nixer policy init --out linux-nixer-policy.json
  linux-nixer policy init --preset workstation --out linux-nixer-policy.json
  linux-nixer policy init --preset server --out linux-nixer-policy.json
  linux-nixer policy init --preset developer-machine --out linux-nixer-policy.json
  linux-nixer policy init --preset minimal-audit --out linux-nixer-policy.json
  linux-nixer capture --policy linux-nixer-policy.json --out linux-nixer-output

Flags:
  --out PATH       Write policy JSON template to PATH. Use - for stdout.
  --preset NAME    Tune the template for a common migration style. One of:
                      workstation        confirm desktop/shell/user config
                      server             confirm services/containers/os-config, exclude desktop config
                      developer-machine  confirm dev projects, git sources, shell config
                      minimal-audit      confirm nothing automatically; review everything by hand
                   Omit for the generic template (autoSafe on, nothing else set).

Policy:
  The template uses schemaVersion "linux-nixer.policy.v1". Policy values supply defaults; explicit CLI boolean and string flags override them, and CLI list flags are merged with policy lists.
`

const policyDiffHelp = `linux-nixer policy diff
Compare two built-in policy presets before choosing one.

Usage:
  linux-nixer policy diff --from workstation --to server [--json]

Examples:
  linux-nixer policy diff --from default --to developer-machine
  linux-nixer policy diff --from server --to minimal-audit --json

Flags:
  --from NAME   Source preset: default, workstation, server, developer-machine, or minimal-audit.
  --to NAME     Target preset: default, workstation, server, developer-machine, or minimal-audit.
  --json        Write machine-readable JSON.
`

func runScan(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, scanHelp)
		return nil
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output scan JSON path")
	policyPath := fs.String("policy", "", "policy JSON path")
	preset := fs.String("preset", "", "built-in policy preset: default, workstation, server, developer-machine, or minimal-audit")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	pluginTimeout := fs.Duration("plugin-timeout", 30*time.Second, "timeout for each plugin scanner invocation")
	var includes multiFlag
	var excludes multiFlag
	var plugins multiFlag
	fs.Var(&includes, "include", "additional path to scan")
	fs.Var(&excludes, "exclude", "path prefix to exclude")
	fs.Var(&plugins, "plugin", "path to an external scanner plugin executable. Repeatable.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("scan requires --out; try `linux-nixer scan --out scan.json`")
	}
	p, err := loadPolicyFromFlags(*policyPath, *preset)
	if err != nil {
		return err
	}
	opts, err := scannerOptionsFromFlags(fs, p, *root, *useSudo, *deep, *baselineID, includes, excludes)
	if err != nil {
		return err
	}
	reg := scanner.DefaultRegistry(pluginScanners(policy.Merge(plugins, p.Plugins), *pluginTimeout)...)
	report, err := reg.Scan(ctx, opts)
	if err != nil {
		return err
	}
	addPluginTrustWarning(report, policy.Merge(plugins, p.Plugins))
	return writeJSON(*out, report)
}

func pluginScanners(paths []string, timeout time.Duration) []scanner.Scanner {
	scanners := make([]scanner.Scanner, len(paths))
	for i, path := range paths {
		scanners[i] = scanner.PluginScanner{Path: path, Timeout: timeout}
	}
	return scanners
}

func runCapture(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, captureHelp)
		return nil
	}
	startedAt := time.Now().UTC()
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output directory")
	policyPath := fs.String("policy", "", "policy JSON path")
	preset := fs.String("preset", "", "built-in policy preset: default, workstation, server, developer-machine, or minimal-audit")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	autoSafe := fs.Bool("auto-safe", true, "confirm high-confidence safe findings during capture")
	failOnPending := fs.Bool("fail-on-pending", false, "fail if candidate or todo findings remain after capture")
	importDecisions := fs.String("import-decisions", "", "seed decisions from a previously exported decisions JSON")
	exportDecisions := fs.String("export-decisions", "", "write final decisions to a portable decisions JSON")
	pluginTimeout := fs.Duration("plugin-timeout", 30*time.Second, "timeout for each plugin scanner invocation")
	var includes multiFlag
	var excludes multiFlag
	var plugins multiFlag
	fs.Var(&includes, "include", "additional path to scan")
	fs.Var(&excludes, "exclude", "path prefix to exclude")
	fs.Var(&plugins, "plugin", "path to an external scanner plugin executable. Repeatable.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("capture requires --out; try `linux-nixer capture --out linux-nixer-output`")
	}
	p, err := loadPolicyFromFlags(*policyPath, *preset)
	if err != nil {
		return err
	}
	scanOpts, err := scannerOptionsFromFlags(fs, p, *root, *useSudo, *deep, *baselineID, includes, excludes)
	if err != nil {
		return err
	}
	pluginPaths := policy.Merge(plugins, p.Plugins)

	reg := scanner.DefaultRegistry(pluginScanners(pluginPaths, *pluginTimeout)...)
	report, err := reg.Scan(ctx, scanOpts)
	if err != nil {
		return err
	}
	addPluginTrustWarning(report, pluginPaths)

	scanPath := filepath.Join(*out, "scan.json")
	reviewedPath := filepath.Join(*out, "reviewed.json")
	summaryPath := filepath.Join(*out, "summary.md")
	sessionPath := filepath.Join(*out, "session.json")
	nixConfigPath := filepath.Join(*out, "nix-config")

	if err := writeJSON(scanPath, report); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote scan: %s\n", scanPath)

	scanReport := *report
	if *importDecisions != "" {
		set, err := loadDecisionSet(*importDecisions)
		if err != nil {
			return err
		}
		scanReport = review.ApplyDecisions(scanReport, set)
	}

	reviewOpts := reviewOptionsFromFlags(fs, p, review.Options{AutoSafe: true}, *autoSafe, nil, nil, nil, nil, nil, nil, false)
	reviewed := review.Apply(scanReport, reviewOpts)
	if err := writeJSON(reviewedPath, reviewed); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote reviewed scan: %s\n", reviewedPath)

	if *exportDecisions != "" {
		if err := writeJSON(*exportDecisions, review.ExportDecisions(reviewed)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote decisions: %s\n", *exportDecisions)
	}

	summary := review.Summarize(reviewed)
	if err := writeText(summaryPath, review.FormatSummaryMarkdown(summary)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote summary: %s\n", summaryPath)

	if *failOnPending && summary.Pending > 0 {
		return fmt.Errorf("capture summary has %d pending findings", summary.Pending)
	}

	if err := render.Project(nixConfigPath, reviewed); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote nix config: %s\n", nixConfigPath)
	session := captureSessionMetadata{
		SchemaVersion: "linux-nixer.capture-session.v1",
		Version:       version,
		Commit:        commit,
		Built:         date,
		StartedAt:     startedAt.Format(time.RFC3339),
		FinishedAt:    time.Now().UTC().Format(time.RFC3339),
		Scan: captureScanMetadata{
			Root:          scanOpts.Root,
			Sudo:          scanOpts.UseSudo,
			Deep:          scanOpts.Deep,
			Baseline:      scanOpts.BaselineID,
			PolicyPath:    *policyPath,
			Preset:        *preset,
			IncludePaths:  append([]string{}, scanOpts.Includes...),
			ExcludePaths:  append([]string{}, scanOpts.Excludes...),
			Plugins:       append([]string{}, pluginPaths...),
			PluginTimeout: pluginTimeout.String(),
		},
		Review: captureReviewMeta{
			AutoSafe:        reviewOpts.AutoSafe,
			FailOnPending:   *failOnPending,
			ImportDecisions: *importDecisions,
			ExportDecisions: *exportDecisions,
		},
		Artifacts: []string{
			"scan.json",
			"reviewed.json",
			"summary.md",
			"session.json",
			"nix-config/",
		},
	}
	if err := writeJSON(sessionPath, session); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote session metadata: %s\n", sessionPath)
	return nil
}

func runRescan(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, rescanHelp)
		return nil
	}
	fs := flag.NewFlagSet("rescan", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output directory")
	policyPath := fs.String("policy", "", "policy JSON path")
	preset := fs.String("preset", "", "built-in policy preset: default, workstation, server, developer-machine, or minimal-audit")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	importDecisions := fs.String("import-decisions", "", "seed decisions from a previously exported decisions JSON")
	compareDecisions := fs.String("compare-decisions", "", "compare against a previously exported decisions JSON")
	pluginTimeout := fs.Duration("plugin-timeout", 30*time.Second, "timeout for each plugin scanner invocation")
	var includes multiFlag
	var excludes multiFlag
	var plugins multiFlag
	fs.Var(&includes, "include", "additional path to scan")
	fs.Var(&excludes, "exclude", "path prefix to exclude")
	fs.Var(&plugins, "plugin", "path to an external scanner plugin executable. Repeatable.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("rescan requires --out; try `linux-nixer rescan --out linux-nixer-rescan --import-decisions decisions.json`")
	}
	if *importDecisions == "" {
		return errors.New("rescan requires --import-decisions; export decisions with `linux-nixer review --export-decisions decisions.json` first")
	}
	p, err := loadPolicyFromFlags(*policyPath, *preset)
	if err != nil {
		return err
	}
	scanOpts, err := scannerOptionsFromFlags(fs, p, *root, *useSudo, *deep, *baselineID, includes, excludes)
	if err != nil {
		return err
	}
	pluginPaths := policy.Merge(plugins, p.Plugins)
	reg := scanner.DefaultRegistry(pluginScanners(pluginPaths, *pluginTimeout)...)
	report, err := reg.Scan(ctx, scanOpts)
	if err != nil {
		return err
	}
	addPluginTrustWarning(report, pluginPaths)

	scanPath := filepath.Join(*out, "scan.json")
	reviewedPath := filepath.Join(*out, "reviewed.json")
	summaryPath := filepath.Join(*out, "summary.md")
	if err := writeJSON(scanPath, report); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote scan: %s\n", scanPath)

	imported, err := loadDecisionSet(*importDecisions)
	if err != nil {
		return err
	}
	reviewed := review.Apply(review.ApplyDecisions(*report, imported), p.ReviewOptions(review.Options{AutoSafe: true}))
	if err := writeJSON(reviewedPath, reviewed); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote reviewed scan: %s\n", reviewedPath)

	comparePath := *compareDecisions
	if comparePath == "" {
		comparePath = *importDecisions
	}
	previous, err := loadDecisionSet(comparePath)
	if err != nil {
		return err
	}
	summary := review.Summarize(reviewed)
	progress := review.ComputeProgress(reviewed, previous)
	summaryText := review.FormatSummaryMarkdown(summary) + "\n" + review.FormatProgressMarkdown(progress)
	if err := writeText(summaryPath, summaryText); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote summary: %s\n", summaryPath)
	return nil
}

func addPluginTrustWarning(report *model.ScanReport, pluginPaths []string) {
	if len(pluginPaths) == 0 {
		return
	}
	report.Warnings = append(report.Warnings, model.Warning{
		Source:  "plugin",
		Message: "scanner plugins are arbitrary executables provided by the user or policy; review plugin paths and generated findings before trusting rendered Nix output",
	})
}

func runReview(args []string, stdin io.Reader, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, reviewHelp)
		return nil
	}
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input scan JSON")
	out := fs.String("out", "", "output reviewed JSON")
	policyPath := fs.String("policy", "", "policy JSON path")
	autoSafe := fs.Bool("auto-safe", false, "confirm high-confidence safe findings")
	interactive := fs.Bool("interactive", false, "review findings interactively")
	pendingOnly := fs.Bool("pending-only", false, "in interactive mode, only prompt for findings still needing a decision")
	importDecisions := fs.String("import-decisions", "", "seed decisions from a previously exported decisions JSON")
	exportDecisions := fs.String("export-decisions", "", "write final decisions to a portable decisions JSON")
	var confirmKinds multiFlag
	var excludeKinds multiFlag
	var todoKinds multiFlag
	var noteKinds multiFlag
	var confirmManagers multiFlag
	var excludePaths multiFlag
	fs.Var(&confirmKinds, "confirm-kind", "mark findings of kind/category as confirmed")
	fs.Var(&excludeKinds, "exclude-kind", "mark findings of kind/category as excluded")
	fs.Var(&todoKinds, "todo-kind", "mark findings of kind/category as todo")
	fs.Var(&noteKinds, "migration-note-kind", "mark findings of kind/category as migration-note")
	fs.Var(&confirmManagers, "confirm-manager", "mark packages from manager as confirmed")
	fs.Var(&excludePaths, "exclude-path", "exclude findings with path prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" || *out == "" {
		return errors.New("review requires --scan and --out; try `linux-nixer review --scan scan.json --out reviewed.json`")
	}
	var report model.ScanReport
	if err := readJSON(*scanPath, &report); err != nil {
		return err
	}
	if *importDecisions != "" {
		set, err := loadDecisionSet(*importDecisions)
		if err != nil {
			return err
		}
		report = review.ApplyDecisions(report, set)
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	opts := reviewOptionsFromFlags(fs, p, review.Options{}, *autoSafe, confirmKinds, excludeKinds, todoKinds, noteKinds, confirmManagers, excludePaths, *pendingOnly)
	if *interactive {
		report = review.Interactive(stdin, stdout, report, opts)
	} else {
		report = review.Apply(report, opts)
	}
	if *exportDecisions != "" {
		if err := writeJSON(*exportDecisions, review.ExportDecisions(report)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote decisions: %s\n", *exportDecisions)
	}
	return writeJSON(*out, &report)
}

func runSummary(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, summaryHelp)
		return nil
	}
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input reviewed scan JSON")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON summary")
	failOnPending := fs.Bool("fail-on-pending", false, "fail if candidate or todo findings remain")
	compareDecisions := fs.String("compare-decisions", "", "compare against a previously exported decisions JSON to report migration progress")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" {
		return errors.New("summary requires --scan; try `linux-nixer summary --scan reviewed.json`")
	}
	var report model.ScanReport
	if err := readJSON(*scanPath, &report); err != nil {
		return err
	}
	summary := review.Summarize(report)
	var progress *review.Progress
	if *compareDecisions != "" {
		previous, err := loadDecisionSet(*compareDecisions)
		if err != nil {
			return err
		}
		p := review.ComputeProgress(report, previous)
		progress = &p
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if progress != nil {
			if err := enc.Encode(struct {
				review.Summary
				Progress *review.Progress `json:"progress,omitempty"`
			}{Summary: summary, Progress: progress}); err != nil {
				return err
			}
		} else if err := enc.Encode(summary); err != nil {
			return err
		}
	} else {
		fmt.Fprint(stdout, review.FormatSummaryMarkdown(summary))
		if progress != nil {
			fmt.Fprint(stdout, "\n")
			fmt.Fprint(stdout, review.FormatProgressMarkdown(*progress))
		}
	}
	if *failOnPending && summary.Pending > 0 {
		return fmt.Errorf("summary has %d pending findings", summary.Pending)
	}
	return nil
}

func runValidate(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, validateHelp)
		return nil
	}
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input scan JSON")
	decisionsPath := fs.String("decisions", "", "decisions JSON to check for consistency with --policy")
	policyPath := fs.String("policy", "", "policy JSON to check --decisions against")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON validation result")
	strict := fs.Bool("strict", false, "reject unknown JSON fields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" && *decisionsPath == "" {
		return errors.New("validate requires --scan or --decisions; try `linux-nixer validate --scan reviewed.json --strict`")
	}
	if *decisionsPath != "" && *policyPath == "" {
		return errors.New("validate --decisions requires --policy; try `linux-nixer validate --decisions decisions.json --policy linux-nixer-policy.json`")
	}

	var subjects []string
	result := validate.Result{OK: true}
	if *scanPath != "" {
		subjects = append(subjects, "scan")
		var report model.ScanReport
		if *strict {
			if err := readJSONStrict(*scanPath, &report); err != nil {
				result := validate.Result{
					OK:     false,
					Errors: []validate.Issue{{Path: *scanPath, Message: err.Error()}},
				}
				if err := writeValidateResult(stdout, "scan", result, *jsonOutput); err != nil {
					return err
				}
				return fmt.Errorf("validation failed with 1 error")
			}
		} else if err := readJSON(*scanPath, &report); err != nil {
			return err
		}
		result = validate.ScanReport(report)
	}

	if *decisionsPath != "" {
		subjects = append(subjects, "decisions")
		set, err := loadDecisionSet(*decisionsPath)
		if err != nil {
			return err
		}
		p, err := policy.Load(*policyPath)
		if err != nil {
			return err
		}
		result = mergeValidateResults(result, policy.CheckDecisions(set, p))
	}

	if err := writeValidateResult(stdout, strings.Join(subjects, " and "), result, *jsonOutput); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("validation failed with %d errors", len(result.Errors))
	}
	return nil
}

func writeValidateResult(stdout io.Writer, subject string, result validate.Result, jsonOutput bool) error {
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Fprint(stdout, formatValidateText(subject, result))
	return nil
}

// formatValidateText mirrors validate.FormatText's layout, parameterized by
// what was actually checked ("scan", "decisions", or "scan and decisions")
// instead of FormatText's fixed "scan" wording, since validate can now run
// independently of any scan file.
func formatValidateText(subject string, result validate.Result) string {
	var b strings.Builder
	if result.OK {
		fmt.Fprintf(&b, "valid %s: checked %d findings\n", subject, result.Checked)
	} else {
		fmt.Fprintf(&b, "invalid %s: %d errors, checked %d findings\n", subject, len(result.Errors), result.Checked)
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

func mergeValidateResults(a, b validate.Result) validate.Result {
	return validate.Result{
		OK:       a.OK && b.OK,
		Checked:  a.Checked + b.Checked,
		Errors:   append(append([]validate.Issue{}, a.Errors...), b.Errors...),
		Warnings: append(append([]validate.Issue{}, a.Warnings...), b.Warnings...),
	}
}

func runPlugin(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 1 && hasHelp(args) {
		fmt.Fprint(stdout, pluginCheckHelp)
		return nil
	}
	if len(args) == 0 || args[0] != "check" {
		return errors.New("plugin supports only: plugin check")
	}
	return runPluginCheck(ctx, args[1:], stdout)
}

func runPluginCheck(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, pluginCheckHelp)
		return nil
	}
	fs := flag.NewFlagSet("plugin check", flag.ContinueOnError)
	fs.SetOutput(stdout)
	pluginPath := fs.String("plugin", "", "path to the plugin executable to check")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout for the plugin invocation")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON validation result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pluginPath == "" {
		return errors.New("plugin check requires --plugin; try `linux-nixer plugin check --plugin ./my-scanner`")
	}

	report, err := scanner.CheckPlugin(ctx, *pluginPath, *timeout)
	if err != nil {
		result := validate.Result{
			OK:     false,
			Errors: []validate.Issue{{Path: *pluginPath, Message: err.Error()}},
		}
		if writeErr := writePluginCheckResult(stdout, *pluginPath, result, *jsonOutput); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("plugin check failed: %v", err)
	}

	result := validate.ScanReport(report)
	if err := writePluginCheckResult(stdout, *pluginPath, result, *jsonOutput); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("plugin check failed with %d errors", len(result.Errors))
	}
	return nil
}

func writePluginCheckResult(stdout io.Writer, pluginPath string, result validate.Result, jsonOutput bool) error {
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	fmt.Fprint(stdout, formatPluginCheckText(pluginPath, result))
	return nil
}

func formatPluginCheckText(pluginPath string, result validate.Result) string {
	var b strings.Builder
	if result.OK {
		fmt.Fprintf(&b, "plugin OK: %s (checked %d findings)\n", pluginPath, result.Checked)
	} else {
		fmt.Fprintf(&b, "plugin check failed: %s (%d errors, checked %d findings)\n", pluginPath, len(result.Errors), result.Checked)
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

func runGenerate(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, generateHelp)
		return nil
	}
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input reviewed scan JSON")
	out := fs.String("out", "", "output flake directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" || *out == "" {
		return errors.New("generate requires --scan and --out; try `linux-nixer generate --scan reviewed.json --out nix-config`")
	}
	var report model.ScanReport
	if err := readJSON(*scanPath, &report); err != nil {
		return err
	}
	result := validate.ScanReport(report)
	if !result.OK {
		return fmt.Errorf("generate requires valid reviewed scan JSON: validation failed with %d errors", len(result.Errors))
	}
	return render.Project(*out, report)
}

func runDoctor(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, doctorHelp)
		return nil
	}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stdout)
	project := fs.String("project", "", "generated flake project")
	vm := fs.Bool("vm", false, "attempt VM validation")
	boot := fs.Bool("boot", false, "attempt to start the generated VM script")
	timeout := fs.Duration("timeout", 15*time.Second, "VM boot validation timeout")
	host := fs.String("host", "", "NixOS configuration name for VM validation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *project == "" {
		return errors.New("doctor requires --project; try `linux-nixer doctor --project nix-config`")
	}
	result := doctor.Run(ctx, doctor.Options{Project: *project, VM: *vm, Boot: *boot, Timeout: *timeout, Host: *host})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	if !result.OK {
		failed := 0
		for _, c := range result.Checks {
			if !c.OK {
				failed++
			}
		}
		return fmt.Errorf("doctor checks failed: %d of %d checks failed", failed, len(result.Checks))
	}
	return nil
}

func runBaseline(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 1 && hasHelp(args) {
		fmt.Fprint(stdout, baselineCreateHelp)
		return nil
	}
	if len(args) == 0 {
		return errors.New("baseline supports: baseline create, baseline fetch, baseline import, baseline list, baseline check; run `linux-nixer help baseline fetch` for common baseline setup")
	}
	switch args[0] {
	case "create":
		return runBaselineCreate(ctx, args[1:], stdout)
	case "fetch":
		return runBaselineFetch(ctx, args[1:], stdout)
	case "import":
		return runBaselineImport(ctx, args[1:], stdin, stdout)
	case "list":
		return runBaselineList(args[1:], stdout)
	case "check":
		return runBaselineCheck(ctx, args[1:], stdout)
	default:
		return errors.New("baseline supports: baseline create, baseline fetch, baseline import, baseline list, baseline check; run `linux-nixer baseline list` to see supported fetch targets")
	}
}

func runBaselineCheck(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, baselineCheckHelp)
		return nil
	}
	fs := flag.NewFlagSet("baseline check", flag.ContinueOnError)
	fs.SetOutput(stdout)
	backend := fs.String("backend", "", "container backend: docker or podman")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	failOnDrift := fs.Bool("fail-on-drift", false, "exit non-zero if any catalog entry has drifted or could not be checked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	results, err := baseline.CheckCatalog(ctx, baseline.CatalogCheckOptions{Backend: *backend})
	if err != nil {
		return err
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return err
		}
	} else {
		for _, r := range results {
			if r.Error != "" {
				fmt.Fprintf(stdout, "%s %s: error: %s\n", r.Distro, r.Release, r.Error)
				continue
			}
			status := "ok"
			if r.Drifted {
				status = "DRIFTED"
			}
			fmt.Fprintf(stdout, "%s %s: %s (pinned: %s, current: %s)\n", r.Distro, r.Release, status, r.PinnedDigest, r.CurrentDigest)
		}
	}
	if *failOnDrift {
		for _, r := range results {
			if r.Drifted || r.Error != "" {
				return errors.New("baseline catalog check found drift or errors; see output above")
			}
		}
	}
	return nil
}

func runBaselineList(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, baselineListHelp)
		return nil
	}
	fs := flag.NewFlagSet("baseline list", flag.ContinueOnError)
	fs.SetOutput(stdout)
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	entries := baseline.CatalogEntries()
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	for _, entry := range entries {
		fmt.Fprintf(stdout, "%s %s (image: %s, digest: %s)\n", entry.Distro, entry.Release, entry.Image, entry.Digest)
	}
	return nil
}

func runBaselineCreate(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, baselineCreateHelp)
		return nil
	}
	fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	fs.SetOutput(stdout)
	distro := fs.String("distro", "", "distro name")
	release := fs.String("release", "", "release version")
	root := fs.String("root", "/", "rootfs path to manifest")
	out := fs.String("out", "", "output baseline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *distro == "" || *release == "" || *out == "" {
		return errors.New("baseline create requires --distro, --release, and --out; try `linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baselines/ubuntu-24.04.json`")
	}
	manifest, err := baseline.Create(ctx, *distro, *release, *root)
	if err != nil {
		return err
	}
	return writeJSON(*out, manifest)
}

func runBaselineFetch(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, baselineFetchHelp)
		return nil
	}
	fs := flag.NewFlagSet("baseline fetch", flag.ContinueOnError)
	fs.SetOutput(stdout)
	distro := fs.String("distro", "", "distro name")
	release := fs.String("release", "", "release version")
	backend := fs.String("backend", "", "container backend: docker or podman")
	offline := fs.Bool("offline", false, "use a bundled manifest instead of pulling a live image")
	out := fs.String("out", "", "output baseline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *distro == "" || *release == "" {
		return errors.New("baseline fetch requires --distro and --release; try `linux-nixer baseline fetch --distro ubuntu --release 24.04 --offline`")
	}
	outPath := *out
	if outPath == "" {
		name, ok := baseline.NormalizeID(*distro + ":" + *release)
		if !ok {
			return fmt.Errorf("invalid distro/release for default output path; pass --out explicitly, e.g. `--out baselines/custom.json`")
		}
		outPath = filepath.Join("baselines", name)
	}
	var manifest *baseline.Manifest
	var err error
	if *offline {
		bundled, ok, bundledErr := baseline.BundledManifest(*distro, *release)
		if bundledErr != nil {
			return bundledErr
		}
		if !ok {
			return fmt.Errorf("no bundled manifest for %s:%s; run \"linux-nixer baseline list\" for what's bundled offline", *distro, *release)
		}
		manifest = bundled
	} else {
		manifest, err = baseline.Fetch(ctx, baseline.FetchOptions{Distro: *distro, Release: *release, Backend: *backend})
		if err != nil {
			return err
		}
	}
	if err := writeJSON(outPath, manifest); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote baseline: %s\n", outPath)
	return nil
}

func runBaselineImport(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, baselineImportHelp)
		return nil
	}
	fs := flag.NewFlagSet("baseline import", flag.ContinueOnError)
	fs.SetOutput(stdout)
	distro := fs.String("distro", "", "distro name")
	release := fs.String("release", "", "release version")
	tarPath := fs.String("tar", "", "path to a flat rootfs tar (or tar.gz); use - for stdin")
	out := fs.String("out", "", "output baseline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *distro == "" || *release == "" || *tarPath == "" {
		return errors.New("baseline import requires --distro, --release, and --tar")
	}
	outPath := *out
	if outPath == "" {
		name, ok := baseline.NormalizeID(*distro + ":" + *release)
		if !ok {
			return fmt.Errorf("invalid distro/release for default output path; pass --out explicitly")
		}
		outPath = filepath.Join("baselines", name)
	}
	manifest, err := baseline.Import(ctx, baseline.ImportOptions{Distro: *distro, Release: *release, TarPath: *tarPath, Stdin: stdin})
	if err != nil {
		return err
	}
	if err := writeJSON(outPath, manifest); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote baseline: %s\n", outPath)
	return nil
}

func runPolicy(args []string, stdout io.Writer) error {
	if len(args) == 1 && hasHelp(args) {
		fmt.Fprint(stdout, policyInitHelp)
		return nil
	}
	if len(args) == 0 {
		return errors.New("policy supports: policy init, policy diff")
	}
	switch args[0] {
	case "init":
		return runPolicyInit(args[1:], stdout)
	case "diff":
		return runPolicyDiff(args[1:], stdout)
	default:
		return errors.New("policy supports: policy init, policy diff")
	}
}

func runPolicyInit(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, policyInitHelp)
		return nil
	}
	fs := flag.NewFlagSet("policy init", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output policy JSON")
	preset := fs.String("preset", "", "policy preset: workstation, server, developer-machine, or minimal-audit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "-" {
		tmpl, err := policy.Template(*preset)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(tmpl)
	}
	if err := policy.WriteTemplate(*out, *preset); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote policy: %s\n", *out)
	return nil
}

func runPolicyDiff(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, policyDiffHelp)
		return nil
	}
	fs := flag.NewFlagSet("policy diff", flag.ContinueOnError)
	fs.SetOutput(stdout)
	from := fs.String("from", "", "source policy preset")
	to := fs.String("to", "", "target policy preset")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	diff, err := policy.DiffPresets(*from, *to)
	if err != nil {
		return err
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	}
	fmt.Fprint(stdout, formatPolicyDiff(diff))
	return nil
}

func formatPolicyDiff(diff policy.PresetDiff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Policy preset diff: %s -> %s\n\n", diff.From, diff.To)
	if diff.AutoSafeChanged {
		fmt.Fprintf(&b, "- autoSafe: %t -> %t\n", diff.FromAutoSafe, diff.ToAutoSafe)
	} else {
		fmt.Fprintf(&b, "- autoSafe: unchanged (%t)\n", diff.FromAutoSafe)
	}
	if len(diff.Fields) == 0 {
		b.WriteString("- list fields: no changes\n")
		return b.String()
	}
	for _, field := range diff.Fields {
		fmt.Fprintf(&b, "- %s", field.Name)
		if len(field.Added) > 0 {
			fmt.Fprintf(&b, " added=%s", strings.Join(field.Added, ","))
		}
		if len(field.Removed) > 0 {
			fmt.Fprintf(&b, " removed=%s", strings.Join(field.Removed, ","))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// loadPolicyFromFlags resolves a Policy from either a --preset name (a
// built-in policy.Template, for a one-shot run with no separate policy
// file) or a --policy file path (for a customized policy) — the two are
// mutually exclusive alternatives, not combinable, so there's exactly one
// source of policy settings for a given invocation.
func loadPolicyFromFlags(policyPath, preset string) (policy.Policy, error) {
	if policyPath != "" && preset != "" {
		return policy.Policy{}, errors.New("--policy and --preset are mutually exclusive; use --preset for a built-in preset or --policy for a custom policy file")
	}
	if preset != "" {
		return policy.Template(preset)
	}
	return policy.Load(policyPath)
}

func scannerOptionsFromFlags(fs *flag.FlagSet, p policy.Policy, root string, useSudo bool, deep bool, baselineID string, includes []string, excludes []string) (scanner.Options, error) {
	opts := p.ScanOptions(scanner.Options{Root: root})
	if flagSpecified(fs, "sudo") {
		opts.UseSudo = useSudo
	}
	if flagSpecified(fs, "deep") {
		opts.Deep = deep
	}
	if flagSpecified(fs, "baseline") {
		opts.BaselineID = baselineID
	}
	opts.Includes = policy.Merge(includes, opts.Includes)
	opts.Excludes = policy.Merge(excludes, opts.Excludes)
	resolvedBaseline, err := resolveBaselineID(opts.BaselineID)
	if err != nil {
		return scanner.Options{}, err
	}
	opts.BaselineID = resolvedBaseline
	return opts, nil
}

func reviewOptionsFromFlags(fs *flag.FlagSet, p policy.Policy, base review.Options, autoSafe bool, confirmKinds []string, excludeKinds []string, todoKinds []string, noteKinds []string, confirmManagers []string, excludePaths []string, pendingOnly bool) review.Options {
	opts := p.ReviewOptions(base)
	if flagSpecified(fs, "auto-safe") {
		opts.AutoSafe = autoSafe
	}
	opts.ConfirmKinds = policy.Merge(confirmKinds, opts.ConfirmKinds)
	opts.ExcludeKinds = policy.Merge(excludeKinds, opts.ExcludeKinds)
	opts.TODOKinds = policy.Merge(todoKinds, opts.TODOKinds)
	opts.MigrationNoteKinds = policy.Merge(noteKinds, opts.MigrationNoteKinds)
	opts.ConfirmManagers = policy.Merge(confirmManagers, opts.ConfirmManagers)
	opts.ExcludePathPrefixes = policy.Merge(excludePaths, opts.ExcludePathPrefixes)
	opts.PendingOnly = pendingOnly
	return opts
}

func resolveBaselineID(baselineID string) (string, error) {
	if baselineID == "" {
		return "", nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if resolution := baseline.Resolve(baselineID, cwd); resolution.OK {
		return resolution.Path, nil
	}
	return baselineID, nil
}

func flagSpecified(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func writeText(path string, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(value)
}

func readJSONStrict(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	return dec.Decode(value)
}

func loadDecisionSet(path string) (review.DecisionSet, error) {
	var set review.DecisionSet
	if err := readJSONStrict(path, &set); err != nil {
		return review.DecisionSet{}, err
	}
	return set, set.Validate()
}
