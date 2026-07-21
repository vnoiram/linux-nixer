// catalog.go is a conservative, hand-verified list of distro/release
// combinations known to correspond to a real official Docker Hub image,
// in the same spirit as internal/mapping's package mapping table: an
// unlisted distro/release stays unlisted rather than being passed through
// to a docker/podman pull that might fail opaquely or, worse, silently
// pull an unexpected image.
//
// See DESIGN_AND_ROADMAP.md's "Baseline catalog maintenance" section for
// the review checklist to follow before adding a new entry.
package baseline

import (
	"sort"
	"strings"
)

var catalog = map[string]map[string]string{
	"ubuntu": {
		"20.04": "ubuntu:20.04",
		"22.04": "ubuntu:22.04",
		"24.04": "ubuntu:24.04",
	},
	"debian": {
		"11": "debian:11",
		"12": "debian:12",
	},
}

// CatalogImage returns the verified Docker Hub image reference for a
// distro/release pair, or "", false if the combination isn't in the
// curated catalog.
func CatalogImage(distro, release string) (string, bool) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	release = strings.TrimSpace(release)
	table := catalog[distro]
	if table == nil {
		return "", false
	}
	image, ok := table[release]
	return image, ok
}

// CatalogEntry is one distro/release/image tuple from the curated catalog.
type CatalogEntry struct {
	Distro  string
	Release string
	Image   string
}

// CatalogEntries returns every entry in the curated catalog, sorted by
// distro then release, for `baseline list`.
func CatalogEntries() []CatalogEntry {
	var entries []CatalogEntry
	for distro, table := range catalog {
		for release, image := range table {
			entries = append(entries, CatalogEntry{Distro: distro, Release: release, Image: image})
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
