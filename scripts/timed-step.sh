#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$3" != "--" ]; then
  echo "usage: $0 NAME OUT_TSV -- COMMAND [ARGS...]" >&2
  exit 2
fi

name="$1"
out="$2"
shift 3

start="$(date +%s)"
"$@"
end="$(date +%s)"
seconds="$((end - start))"
printf '%s\t%s\n' "$name" "$seconds" >> "$out"

