package baseline

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type FetchOptions struct {
	Distro  string
	Release string
	Backend string
	Runner  CommandRunner
}

func Fetch(ctx context.Context, opts FetchOptions) (*Manifest, error) {
	if opts.Distro == "" || opts.Release == "" {
		return nil, fmt.Errorf("fetch requires distro and release")
	}
	image, ok := CatalogImage(opts.Distro, opts.Release)
	if !ok {
		return nil, fmt.Errorf("%s:%s is not in the known baseline catalog; run \"linux-nixer baseline list\" for supported distro/release pairs", opts.Distro, opts.Release)
	}
	digest, ok := CatalogDigest(opts.Distro, opts.Release)
	if !ok {
		return nil, fmt.Errorf("catalog entry for %s:%s has no verified digest; this is a catalog bug, not a user error", opts.Distro, opts.Release)
	}
	// Pull by the verified digest, not the floating tag: a tag like
	// "ubuntu:24.04" gets silently rebuilt over time, which would break
	// baseline reproducibility (see catalog.go's package doc). Also fully
	// qualify to Docker Hub explicitly, not a bare tag, so the result can't
	// depend on local registry-alias configuration (see
	// dockerHubOfficialRegistry's doc comment).
	pullRef := qualifiedImageRef(image) + "@" + digest

	backend := opts.Backend
	if backend == "" {
		if opts.Runner != nil {
			return nil, fmt.Errorf("backend must be specified when using a custom runner")
		}
		backend = detectHostBackend()
		if backend == "" {
			return nil, fmt.Errorf("no container backend found; install docker or podman, or pass --backend")
		}
	}

	container := fmt.Sprintf("linux-nixer-baseline-%d", time.Now().UnixNano())
	run := func(args ...string) ([]byte, error) {
		return runCommand(ctx, opts.Runner, backend, args...)
	}

	if _, err := run("pull", pullRef); err != nil {
		return nil, fmt.Errorf("pulling %s via %s: %w", pullRef, backend, err)
	}
	if _, err := run("create", "--name", container, pullRef); err != nil {
		return nil, fmt.Errorf("creating container from %s: %w", pullRef, err)
	}
	defer run("rm", "-f", container)

	exported, err := run("export", container)
	if err != nil {
		return nil, fmt.Errorf("exporting %s: %w", container, err)
	}

	tempDir, err := os.MkdirTemp("", "linux-nixer-baseline-fetch")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	if err := extractTar(exported, tempDir); err != nil {
		return nil, fmt.Errorf("extracting %s rootfs: %w", pullRef, err)
	}

	manifest, err := Create(ctx, opts.Distro, opts.Release, tempDir)
	if err != nil {
		return nil, err
	}
	manifest.Source = backend + ":" + pullRef
	return manifest, nil
}

func detectHostBackend() string {
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	if _, err := exec.LookPath("podman"); err == nil {
		return "podman"
	}
	return ""
}

func runCommand(ctx context.Context, runner CommandRunner, name string, args ...string) ([]byte, error) {
	if runner != nil {
		return runner(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).Output()
}

func extractTar(data []byte, destDir string) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, ok := safeExtractPath(destDir, header.Name)
		if !ok {
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			if err := writeTarFile(target, mode, tr); err != nil {
				return err
			}
		default:
			continue
		}
	}
}

func writeTarFile(target string, mode os.FileMode, r io.Reader) error {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

func safeExtractPath(destDir, name string) (string, bool) {
	cleaned := filepath.Clean("/" + name)
	target := filepath.Join(destDir, cleaned)
	destPrefix := filepath.Clean(destDir) + string(os.PathSeparator)
	if target != filepath.Clean(destDir) && !strings.HasPrefix(target, destPrefix) {
		return "", false
	}
	return target, true
}
