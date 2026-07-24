package main

import (
	"encoding/json"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "capabilities" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schemaVersion": "linux-nixer.plugin-capabilities.v1",
			"name":          "sample-go-scanner",
			"version":       "0.1.0",
			"author":        "linux-nixer",
			"domains":       []string{"custom-finding"},
			"runtimeNeeds":  []string{"go"},
		})
		return
	}
	_, _ = os.Stdin.Read(make([]byte, 0))
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schemaVersion": "linux-nixer.scan.v1",
		"items": []map[string]string{{
			"kind":     "custom-finding",
			"name":     "go-sample",
			"path":     "/opt/go-sample",
			"decision": "candidate",
			"reason":   "found by go sample plugin",
		}},
	})
}
