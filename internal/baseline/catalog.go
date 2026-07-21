// catalog.go is a conservative, hand-verified list of distro/release
// combinations known to correspond to a real official Docker Hub image,
// in the same spirit as internal/mapping's package mapping table: an
// unlisted distro/release stays unlisted rather than being passed through
// to a docker/podman pull that might fail opaquely or, worse, silently
// pull an unexpected image.
//
// Each entry pins the exact image digest verified at catalog-authoring
// time, not just a floating tag — a tag like "ubuntu:24.04" gets silently
// rebuilt over time, so pulling by tag alone can't guarantee baseline
// fetch produces the same bytes today as it did when the entry was
// verified, or that two people fetching "the same" release get identical
// content. That undermines the entire point of a baseline (a stable
// reference to diff against), so Fetch pulls by digest; refreshing an
// entry's digest to track a new point release is a deliberate, reviewed
// catalog change, not something that happens silently.
//
// See DESIGN_AND_ROADMAP.md's "Baseline catalog maintenance" section for
// the review checklist to follow before adding a new entry.
package baseline

import (
	"sort"
	"strings"
)

type catalogEntry struct {
	image  string // human-readable tag, e.g. "ubuntu:24.04"
	digest string // "sha256:..." verified at catalog-authoring time
}

var catalog = map[string]map[string]catalogEntry{
	"ubuntu": {
		"20.04": {image: "ubuntu:20.04", digest: "sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214"},
		"22.04": {image: "ubuntu:22.04", digest: "sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8"},
		"24.04": {image: "ubuntu:24.04", digest: "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"},
	},
	"debian": {
		"11": {image: "debian:11", digest: "sha256:6cb68b1be980a0e5b19be25582b34b5cf9cb466d52d08ab4354b79051f2cd298"},
		"12": {image: "debian:12", digest: "sha256:41a613df4beca480a97c22b1f6837f7502cb95206e2cc2daf1ea3cb28f8755ab"},
	},
}

// CatalogImage returns the verified Docker Hub image tag for a
// distro/release pair, or "", false if the combination isn't in the
// curated catalog.
func CatalogImage(distro, release string) (string, bool) {
	entry, ok := lookupCatalogEntry(distro, release)
	return entry.image, ok
}

// CatalogDigest returns the verified image digest ("sha256:...") for a
// distro/release pair, or "", false if the combination isn't in the
// curated catalog. Fetch pulls by this digest, not by the floating tag.
func CatalogDigest(distro, release string) (string, bool) {
	entry, ok := lookupCatalogEntry(distro, release)
	return entry.digest, ok
}

func lookupCatalogEntry(distro, release string) (catalogEntry, bool) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	release = strings.TrimSpace(release)
	table := catalog[distro]
	if table == nil {
		return catalogEntry{}, false
	}
	entry, ok := table[release]
	return entry, ok
}

// CatalogEntry is one distro/release/image/digest tuple from the curated
// catalog.
type CatalogEntry struct {
	Distro  string
	Release string
	Image   string
	Digest  string
}

// CatalogEntries returns every entry in the curated catalog, sorted by
// distro then release, for `baseline list`.
func CatalogEntries() []CatalogEntry {
	var entries []CatalogEntry
	for distro, table := range catalog {
		for release, entry := range table {
			entries = append(entries, CatalogEntry{Distro: distro, Release: release, Image: entry.image, Digest: entry.digest})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Distro != entries[j].Distro {
			return entries[i].Distro < entries[j].Distro
		}
		return entries[i].Release < entries[j].Release
	})
	return entries
}
