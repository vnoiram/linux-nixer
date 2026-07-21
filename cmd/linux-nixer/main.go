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
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `linux-nixer converts Debian/Ubuntu environments into NixOS + Home Manager flakes.

Usage:
  linux-nixer scan --out scan.json [--policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH]
  linux-nixer capture --out DIR [--policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--fail-on-pending]
  linux-nixer review --scan scan.json --out reviewed.json [--policy policy.json] [--auto-safe] [--interactive] [--confirm-kind KIND] [--exclude-kind KIND]
  linux-nixer summary --scan reviewed.json [--json] [--fail-on-pending]
  linux-nixer validate --scan reviewed.json [--json] [--strict]
  linux-nixer generate --scan reviewed.json --out ./nix-config
  linux-nixer doctor --project ./nix-config [--vm] [--boot] [--timeout 15s] [--host generated]
  linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baseline.json
  linux-nixer baseline fetch --distro ubuntu --release 24.04 [--backend docker|podman] [--out baselines/ubuntu-24.04.json]
  linux-nixer baseline import --distro ubuntu --release 24.04 --tar PATH [--out baselines/ubuntu-24.04.json]
  linux-nixer policy init --out linux-nixer-policy.json [--preset workstation|server|developer-machine|minimal-audit]
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
		return fmt.Errorf("unknown help topic %q", "baseline "+topic[1])
	case "policy":
		if len(topic) == 1 || topic[1] == "init" {
			fmt.Fprint(w, policyInitHelp)
			return nil
		}
		return fmt.Errorf("unknown help topic %q", "policy "+topic[1])
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
  linux-nixer scan --out scan.json [--policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--plugin PATH]

Examples:
  linux-nixer scan --out scan.json
  linux-nixer scan --sudo --deep --out scan.json
  linux-nixer scan --root /mnt/ubuntu --include /opt --baseline ubuntu:24.04 --out scan.json
  linux-nixer scan --plugin ./my-scanner --out scan.json

Flags:
  --out PATH       Write scan JSON to PATH.
  --policy PATH    Load repeatable scan and review policy from PATH.
  --root PATH      Scan PATH as the root filesystem. Defaults to /.
  --sudo           Allow read-only sudo fallback for selected host files.
  --deep           Scan broader filesystem paths for manual installs and config.
  --baseline ID    Compare filesystem findings against a baseline id or JSON path.
  --include PATH   Add a path to filesystem-diff scanning. Repeatable.
  --exclude PATH   Exclude a path prefix from scanning. Repeatable.
  --plugin PATH    Run an external scanner plugin executable. Repeatable. See "Plugin scanners" in DESIGN_AND_ROADMAP.md for the protocol. Plugins always run as the current user, never with --sudo elevation.

Policy:
  Policy include/exclude lists are merged with CLI list flags. Explicit CLI boolean and string flags override policy values.
`

const captureHelp = `linux-nixer capture
Run scan, auto-safe review, summary, and Nix generation in one workflow.

Usage:
  linux-nixer capture --out DIR [--policy policy.json] [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--plugin PATH] [--auto-safe=false] [--fail-on-pending] [--import-decisions PATH] [--export-decisions PATH]

Examples:
  linux-nixer capture --out linux-nixer-output
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
  --policy PATH             Load repeatable scan and review policy from PATH.
  --root PATH               Scan PATH as the root filesystem. Defaults to /.
  --sudo                    Allow read-only sudo fallback for selected host files.
  --deep                    Scan broader filesystem paths for manual installs and config.
  --baseline ID             Compare filesystem findings against a baseline id or JSON path.
  --include PATH            Add a path to filesystem-diff scanning. Repeatable.
  --exclude PATH            Exclude a path prefix from scanning. Repeatable.
  --plugin PATH             Run an external scanner plugin executable. Repeatable. See "Plugin scanners" in DESIGN_AND_ROADMAP.md for the protocol. Plugins always run as the current user, never with --sudo elevation.
  --auto-safe=false         Disable high-confidence automatic confirmations.
  --fail-on-pending         Return an error if candidate or todo findings remain.
  --import-decisions PATH   Seed decisions from a previously exported decisions JSON before review.
  --export-decisions PATH   Write the final decisions to a portable decisions JSON.

Policy:
  Policy scan and review defaults are applied first. Explicit CLI boolean and string flags override policy values; CLI list flags are merged with policy lists.

Repeatable sessions:
  --export-decisions writes a host-independent record of every non-default decision, keyed by finding identity (e.g. "apt:curl", "systemd:app.service") rather than scan position. --import-decisions seeds a later scan (a re-scan of the same host, or a teammate's scan of a similar one) with those decisions before policy rules run, so previously reviewed findings don't need to be re-decided.
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
Validate scan or reviewed scan JSON before using it for generation or CI gates.

Usage:
  linux-nixer validate --scan reviewed.json [--json] [--strict]

Examples:
  linux-nixer validate --scan reviewed.json
  linux-nixer validate --scan reviewed.json --json
  linux-nixer validate --scan reviewed.json --strict

Flags:
  --scan PATH    Read scan JSON.
  --json         Write machine-readable JSON validation result.
  --strict       Reject unknown JSON fields in addition to semantic validation.
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
  linux-nixer baseline fetch --distro ubuntu --release 24.04 [--backend docker|podman] [--out PATH]

Examples:
  linux-nixer baseline fetch --distro ubuntu --release 24.04
  linux-nixer baseline fetch --distro debian --release 12 --out baselines/debian-12.json
  linux-nixer scan --baseline ubuntu:24.04 --include /opt --out scan.json

Flags:
  --distro NAME      Distro name; also used as the image name (e.g. ubuntu, debian).
  --release VALUE    Distro release version; also used as the image tag (e.g. 24.04, 12).
  --backend NAME     Container backend: docker or podman. Auto-detected from PATH if omitted.
  --out PATH         Write baseline JSON to PATH. Defaults to baselines/<distro>-<release>.json.

Pulls the <distro>:<release> image, exports its filesystem, and builds the manifest from real file contents — no hand-maintained package data.
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

func runScan(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, scanHelp)
		return nil
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output scan JSON path")
	policyPath := fs.String("policy", "", "policy JSON path")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
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
		return errors.New("scan requires --out")
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	opts, err := scannerOptionsFromFlags(fs, p, *root, *useSudo, *deep, *baselineID, includes, excludes)
	if err != nil {
		return err
	}
	reg := scanner.DefaultRegistry(pluginScanners(plugins)...)
	report, err := reg.Scan(ctx, opts)
	if err != nil {
		return err
	}
	return writeJSON(*out, report)
}

func pluginScanners(paths []string) []scanner.Scanner {
	scanners := make([]scanner.Scanner, len(paths))
	for i, path := range paths {
		scanners[i] = scanner.PluginScanner{Path: path}
	}
	return scanners
}

func runCapture(ctx context.Context, args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, captureHelp)
		return nil
	}
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output directory")
	policyPath := fs.String("policy", "", "policy JSON path")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	autoSafe := fs.Bool("auto-safe", true, "confirm high-confidence safe findings during capture")
	failOnPending := fs.Bool("fail-on-pending", false, "fail if candidate or todo findings remain after capture")
	importDecisions := fs.String("import-decisions", "", "seed decisions from a previously exported decisions JSON")
	exportDecisions := fs.String("export-decisions", "", "write final decisions to a portable decisions JSON")
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
		return errors.New("capture requires --out")
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	scanOpts, err := scannerOptionsFromFlags(fs, p, *root, *useSudo, *deep, *baselineID, includes, excludes)
	if err != nil {
		return err
	}

	reg := scanner.DefaultRegistry(pluginScanners(plugins)...)
	report, err := reg.Scan(ctx, scanOpts)
	if err != nil {
		return err
	}

	scanPath := filepath.Join(*out, "scan.json")
	reviewedPath := filepath.Join(*out, "reviewed.json")
	summaryPath := filepath.Join(*out, "summary.md")
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
	return nil
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
		return errors.New("review requires --scan and --out")
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
		return errors.New("summary requires --scan")
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
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON validation result")
	strict := fs.Bool("strict", false, "reject unknown JSON fields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanPath == "" {
		return errors.New("validate requires --scan")
	}
	var report model.ScanReport
	if *strict {
		if err := readJSONStrict(*scanPath, &report); err != nil {
			result := validate.Result{
				OK:     false,
				Errors: []validate.Issue{{Path: *scanPath, Message: err.Error()}},
			}
			if *jsonOutput {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				if encodeErr := enc.Encode(result); encodeErr != nil {
					return encodeErr
				}
			} else {
				fmt.Fprint(stdout, validate.FormatText(result))
			}
			return fmt.Errorf("validation failed with 1 error")
		}
	} else if err := readJSON(*scanPath, &report); err != nil {
		return err
	}
	result := validate.ScanReport(report)
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
	} else {
		fmt.Fprint(stdout, validate.FormatText(result))
	}
	if !result.OK {
		return fmt.Errorf("validation failed with %d errors", len(result.Errors))
	}
	return nil
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
		return errors.New("generate requires --scan and --out")
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
		return errors.New("doctor requires --project")
	}
	result := doctor.Run(ctx, doctor.Options{Project: *project, VM: *vm, Boot: *boot, Timeout: *timeout, Host: *host})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func runBaseline(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 1 && hasHelp(args) {
		fmt.Fprint(stdout, baselineCreateHelp)
		return nil
	}
	if len(args) == 0 {
		return errors.New("baseline supports: baseline create, baseline fetch, baseline import")
	}
	switch args[0] {
	case "create":
		return runBaselineCreate(ctx, args[1:], stdout)
	case "fetch":
		return runBaselineFetch(ctx, args[1:], stdout)
	case "import":
		return runBaselineImport(ctx, args[1:], stdin, stdout)
	default:
		return errors.New("baseline supports: baseline create, baseline fetch, baseline import")
	}
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
		return errors.New("baseline create requires --distro, --release, and --out")
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
	out := fs.String("out", "", "output baseline JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *distro == "" || *release == "" {
		return errors.New("baseline fetch requires --distro and --release")
	}
	outPath := *out
	if outPath == "" {
		name, ok := baseline.NormalizeID(*distro + ":" + *release)
		if !ok {
			return fmt.Errorf("invalid distro/release for default output path; pass --out explicitly")
		}
		outPath = filepath.Join("baselines", name)
	}
	manifest, err := baseline.Fetch(ctx, baseline.FetchOptions{Distro: *distro, Release: *release, Backend: *backend})
	if err != nil {
		return err
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
	if len(args) == 0 || args[0] != "init" {
		return errors.New("policy supports only: policy init")
	}
	if hasHelp(args[1:]) {
		fmt.Fprint(stdout, policyInitHelp)
		return nil
	}
	fs := flag.NewFlagSet("policy init", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output policy JSON")
	preset := fs.String("preset", "", "policy preset: workstation, server, developer-machine, or minimal-audit")
	if err := fs.Parse(args[1:]); err != nil {
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
