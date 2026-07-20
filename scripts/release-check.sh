#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <tag>  (e.g. v0.2.0)" >&2
  exit 2
fi

tag="$1"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! echo "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
  echo "release tag must be vMAJOR.MINOR.PATCH or a SemVer prerelease, got: $tag" >&2
  exit 1
fi

echo "==> changelog check"
scripts/check-changelog.sh "$tag"

echo "==> format check"
test -z "$(gofmt -l cmd internal)"

echo "==> vet"
go vet ./...

echo "==> test"
go test ./...

echo "==> build release archives"
rm -rf dist
mkdir -p dist
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for arch in amd64 arm64; do
  GOOS=linux GOARCH="$arch" go build -ldflags="-s -w -X main.version=${tag} -X main.commit=${commit} -X main.date=${date}" -o "dist/linux-nixer" ./cmd/linux-nixer
  tar -C dist -czf "dist/linux-nixer-${tag}-linux-${arch}.tar.gz" linux-nixer
  rm "dist/linux-nixer"
done
(cd dist && sha256sum *.tar.gz > checksums.txt)

echo "==> smoke test release archives"
for arch in amd64 arm64; do
  work="dist/smoke-${arch}"
  mkdir -p "$work"
  tar -C "$work" -xzf "dist/linux-nixer-${tag}-linux-${arch}.tar.gz"
  grep -a -F "$tag" "$work/linux-nixer" >/dev/null
  if [ "$arch" = "amd64" ]; then
    actual="$("$work/linux-nixer" version)"
    if [ "$actual" != "$tag" ]; then
      echo "version mismatch for ${arch}: got ${actual}, want ${tag}" >&2
      exit 1
    fi
    echo "artifact metadata: $("$work/linux-nixer" version --full)"
  fi
  test -x "$work/linux-nixer"
  rm -rf "$work"
done

echo "release check passed for $tag"
ls -la dist/*.tar.gz dist/checksums.txt
