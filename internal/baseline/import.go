package baseline

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
)

// ImportOptions builds a baseline manifest from an already-downloaded flat
// rootfs tar archive (e.g. an official distro base-rootfs tarball, or the
// output of `docker export`) instead of a live rootfs or a container
// backend — for offline use.
//
// Only flat tars are supported. A `docker save`/OCI multi-layer image tar
// (manifest.json plus per-layer tars with whiteout-file semantics) is a
// different, more complex format that this does not attempt to unpack.
type ImportOptions struct {
	Distro  string
	Release string
	TarPath string    // "-" reads from Stdin
	Stdin   io.Reader // used when TarPath == "-"; defaults to os.Stdin
}

func Import(ctx context.Context, opts ImportOptions) (*Manifest, error) {
	if opts.Distro == "" || opts.Release == "" {
		return nil, fmt.Errorf("import requires distro and release")
	}
	if opts.TarPath == "" {
		return nil, fmt.Errorf("import requires a tar path (use - for stdin)")
	}

	var data []byte
	var err error
	source := "tar:" + opts.TarPath
	if opts.TarPath == "-" {
		stdin := opts.Stdin
		if stdin == nil {
			stdin = os.Stdin
		}
		data, err = io.ReadAll(stdin)
		source = "tar:stdin"
	} else {
		data, err = os.ReadFile(opts.TarPath)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", opts.TarPath, err)
	}

	data, err = maybeGunzip(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", opts.TarPath, err)
	}

	tempDir, err := os.MkdirTemp("", "linux-nixer-baseline-import")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	if err := extractTar(data, tempDir); err != nil {
		return nil, fmt.Errorf("extracting %s: %w", opts.TarPath, err)
	}

	manifest, err := Create(ctx, opts.Distro, opts.Release, tempDir)
	if err != nil {
		return nil, err
	}
	manifest.Source = source
	return manifest, nil
}

func maybeGunzip(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}
