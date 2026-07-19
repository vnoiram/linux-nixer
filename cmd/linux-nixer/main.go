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
	"github.com/vnoiram/linux-nixer/internal/render"
	"github.com/vnoiram/linux-nixer/internal/review"
	"github.com/vnoiram/linux-nixer/internal/scanner"
	"github.com/vnoiram/linux-nixer/internal/validate"
)

var version = "0.1.0-dev"

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
		return runBaseline(ctx, args[1:], stdout)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "--help", "-h":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `linux-nixer converts Debian/Ubuntu environments into NixOS + Home Manager flakes.

Usage:
  linux-nixer scan --out scan.json [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH]
  linux-nixer capture --out DIR [--root /] [--sudo] [--deep] [--baseline ubuntu:24.04] [--include PATH] [--exclude PATH] [--fail-on-pending]
  linux-nixer review --scan scan.json --out reviewed.json [--auto-safe] [--interactive] [--confirm-kind KIND] [--exclude-kind KIND]
  linux-nixer summary --scan reviewed.json [--json] [--fail-on-pending]
  linux-nixer validate --scan reviewed.json [--json] [--strict]
  linux-nixer generate --scan reviewed.json --out ./nix-config
  linux-nixer doctor --project ./nix-config [--vm] [--boot] [--timeout 15s] [--host generated]
  linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baseline.json
  linux-nixer version`)
}

func runScan(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output scan JSON path")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	var includes multiFlag
	var excludes multiFlag
	fs.Var(&includes, "include", "additional path to scan")
	fs.Var(&excludes, "exclude", "path prefix to exclude")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("scan requires --out")
	}
	resolvedBaseline := *baselineID
	if *baselineID != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if resolution := baseline.Resolve(*baselineID, cwd); resolution.OK {
			resolvedBaseline = resolution.Path
		}
	}
	reg := scanner.DefaultRegistry()
	report, err := reg.Scan(ctx, scanner.Options{
		Root:       *root,
		UseSudo:    *useSudo,
		Deep:       *deep,
		BaselineID: resolvedBaseline,
		Includes:   includes,
		Excludes:   excludes,
	})
	if err != nil {
		return err
	}
	return writeJSON(*out, report)
}

func runCapture(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "", "output directory")
	root := fs.String("root", "/", "root filesystem to scan")
	useSudo := fs.Bool("sudo", false, "allow read-only sudo fallback for selected host files")
	deep := fs.Bool("deep", false, "scan broader filesystem paths")
	baselineID := fs.String("baseline", "", "baseline id such as ubuntu:24.04")
	failOnPending := fs.Bool("fail-on-pending", false, "fail if candidate or todo findings remain after capture")
	var includes multiFlag
	var excludes multiFlag
	fs.Var(&includes, "include", "additional path to scan")
	fs.Var(&excludes, "exclude", "path prefix to exclude")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("capture requires --out")
	}

	resolvedBaseline := *baselineID
	if *baselineID != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if resolution := baseline.Resolve(*baselineID, cwd); resolution.OK {
			resolvedBaseline = resolution.Path
		}
	}

	reg := scanner.DefaultRegistry()
	report, err := reg.Scan(ctx, scanner.Options{
		Root:       *root,
		UseSudo:    *useSudo,
		Deep:       *deep,
		BaselineID: resolvedBaseline,
		Includes:   includes,
		Excludes:   excludes,
	})
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

	reviewed := review.Apply(*report, review.Options{AutoSafe: true})
	if err := writeJSON(reviewedPath, reviewed); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote reviewed scan: %s\n", reviewedPath)

	summary := review.Summarize(reviewed)
	if err := writeText(summaryPath, review.FormatSummaryMarkdown(summary)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote summary: %s\n", summaryPath)

	if err := render.Project(nixConfigPath, reviewed); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote nix config: %s\n", nixConfigPath)

	if *failOnPending && summary.Pending > 0 {
		return fmt.Errorf("capture summary has %d pending findings", summary.Pending)
	}
	return nil
}

func runReview(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input scan JSON")
	out := fs.String("out", "", "output reviewed JSON")
	autoSafe := fs.Bool("auto-safe", false, "confirm high-confidence safe findings")
	interactive := fs.Bool("interactive", false, "review findings interactively")
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
	opts := review.Options{
		AutoSafe:            *autoSafe,
		ConfirmKinds:        confirmKinds,
		ExcludeKinds:        excludeKinds,
		TODOKinds:           todoKinds,
		MigrationNoteKinds:  noteKinds,
		ConfirmManagers:     confirmManagers,
		ExcludePathPrefixes: excludePaths,
	}
	if *interactive {
		report = review.Interactive(stdin, stdout, report, opts)
	} else {
		report = review.Apply(report, opts)
	}
	return writeJSON(*out, &report)
}

func runSummary(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	fs.SetOutput(stdout)
	scanPath := fs.String("scan", "", "input reviewed scan JSON")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON summary")
	failOnPending := fs.Bool("fail-on-pending", false, "fail if candidate or todo findings remain")
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
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			return err
		}
	} else {
		fmt.Fprint(stdout, review.FormatSummaryMarkdown(summary))
	}
	if *failOnPending && summary.Pending > 0 {
		return fmt.Errorf("summary has %d pending findings", summary.Pending)
	}
	return nil
}

func runValidate(args []string, stdout io.Writer) error {
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
	return render.Project(*out, report)
}

func runDoctor(ctx context.Context, args []string, stdout io.Writer) error {
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

func runBaseline(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("baseline supports only: baseline create")
	}
	fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	fs.SetOutput(stdout)
	distro := fs.String("distro", "", "distro name")
	release := fs.String("release", "", "release version")
	root := fs.String("root", "/", "rootfs path to manifest")
	out := fs.String("out", "", "output baseline JSON")
	if err := fs.Parse(args[1:]); err != nil {
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
