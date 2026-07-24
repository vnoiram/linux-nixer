//go:build ignore

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type provenance struct {
	SchemaVersion string     `json:"schemaVersion"`
	Tag           string     `json:"tag"`
	Commit        string     `json:"commit"`
	BuiltAt       string     `json:"builtAt"`
	GoVersion     string     `json:"goVersion"`
	Platforms     []string   `json:"platforms"`
	Artifacts     []artifact `json:"artifacts"`
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: provenance TAG COMMIT BUILT_AT GOVERSION")
		os.Exit(2)
	}
	p := provenance{
		SchemaVersion: "linux-nixer.release-provenance.v1",
		Tag:           os.Args[1],
		Commit:        os.Args[2],
		BuiltAt:       os.Args[3],
		GoVersion:     os.Args[4],
		Platforms:     []string{"linux/amd64", "linux/arm64"},
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		p.Artifacts = append(p.Artifacts, artifact{Name: fields[1], SHA256: fields[0]})
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
