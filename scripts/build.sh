#!/usr/bin/env bash
# 编译 subgw 二进制(纯 Go,无 CGO,便于跨平台)
set -e

cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.1.0}"
OUTDIR="${OUTDIR:-./dist}"
mkdir -p "$OUTDIR"

# 默认本机编译
GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
SUFFIX=""
[ "$GOOS" = "windows" ] && SUFFIX=".exe"

OUTBIN="$OUTDIR/subgw-${GOOS}-${GOARCH}${SUFFIX}"

echo ">> building $OUTBIN  (version=$VERSION)"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build -trimpath -ldflags="-s -w -X main.Version=$VERSION" \
  -o "$OUTBIN" ./cmd/subgw

ls -lh "$OUTBIN"
echo ">> done"
