#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
changelog="$root/CHANGELOG.md"
version="${1#v}"
escaped="${version//./\\.}"

if ! grep -qE "^## \[${escaped}\]" "$changelog"; then
  echo "CHANGELOG.md is missing a '## [${version}]' entry" >&2
  exit 1
fi

echo "CHANGELOG.md has an entry for ${version}"
