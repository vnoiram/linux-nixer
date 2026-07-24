#!/usr/bin/env bash
set -euo pipefail

input="${1:-/dev/stdin}"

awk '
BEGIN {
  print "# CI timing report"
  print ""
}
NF >= 2 {
  name=$1
  seconds=$2 + 0
  total += seconds
  count += 1
  if (seconds > max) {
    max = seconds
    slowest = name
  }
  rows[count] = sprintf("| %s | %.3f |", name, seconds)
}
END {
  print "| Step | Seconds |"
  print "| --- | ---: |"
  for (i = 1; i <= count; i++) {
    print rows[i]
  }
  print ""
  printf("- steps: %d\n", count)
  printf("- total seconds: %.3f\n", total)
  if (count > 0) {
    printf("- slowest step: %s (%.3fs)\n", slowest, max)
  }
}
' "$input"

