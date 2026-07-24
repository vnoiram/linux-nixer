#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 TAG COMMIT BUILT_AT GOVERSION" >&2
  exit 2
fi

GOOS= GOARCH= go run ./scripts/write_release_provenance_tool.go "$1" "$2" "$3" "$4"

