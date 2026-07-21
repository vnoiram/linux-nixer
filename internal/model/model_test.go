package model

import "testing"

// TestScanSchemaVersionIsStable pins the literal schema version string.
// This is the schema shared by scan.json/reviewed.json and the plugin
// protocol's required output shape (see DESIGN_AND_ROADMAP.md's
// "Compatibility policy" bullet under "Plugin scanners") — changing it is
// a breaking change for every existing plugin and any tooling reading
// scan/reviewed JSON, and must be a deliberate decision, not an accidental
// edit.
func TestScanSchemaVersionIsStable(t *testing.T) {
	const want = "linux-nixer.scan.v1"
	if SchemaVersion != want {
		t.Fatalf("SchemaVersion changed to %q, want %q — this is a breaking change for every existing plugin and scan/reviewed JSON consumer unless deliberate", SchemaVersion, want)
	}
}
