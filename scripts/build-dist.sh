#!/usr/bin/env bash
# Builds the release trees into dist/, one per git branch:
#   dist/cli-<os>-<arch>  the native binary of one platform (npm os/cpu pick the right one)
#   dist/cli              the Node shim that runs it (platform packages are added by publish-branches.sh)
#   dist/ts-sdk           the TypeScript SDK on WebAssembly
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(cat VERSION)
platforms=${MSECRETS_PLATFORMS-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"}

# Sets "version" (and optionally more top-level fields, as JSON) in a package.json.
set_package() {
  node -e '
    const fs = require("node:fs");
    const [file, version, extra] = process.argv.slice(1);
    const pkg = { ...JSON.parse(fs.readFileSync(file, "utf8")), version, ...JSON.parse(extra || "{}") };
    fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
  ' "$@"
}

rm -rf dist
mkdir -p dist
for target in $platforms; do
  goos=${target%/*} goarch=${target#*/}
  os=${goos/windows/win32} arch=${goarch/amd64/x64}
  dir=dist/cli-$os-$arch ext=
  [ "$goos" = windows ] && ext=.exe
  mkdir -p "$dir/bin"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$dir/bin/msecrets$ext" ./cmd/msecrets
  echo "{}" > "$dir/package.json"
  set_package "$dir/package.json" "$version" "$(printf '{"name":"@msecrets/cli-%s-%s","description":"The msecrets binary for %s %s.","license":"MIT","repository":{"type":"git","url":"git+https://github.com/k18k/msecrets.git"},"os":["%s"],"cpu":["%s"]}' "$os" "$arch" "$os" "$arch" "$os" "$arch")"
  cp LICENSE "$dir/"
done

cp -R npm/cli dist/cli
cp LICENSE dist/cli/
set_package dist/cli/package.json "$version"

cp -R sdk/js dist/ts-sdk
mkdir -p dist/ts-sdk/schema
cp schema/v4.json dist/ts-sdk/schema/
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/ts-sdk/
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o dist/ts-sdk/msecrets.wasm ./sdk/wasm
cp LICENSE dist/ts-sdk/
set_package dist/ts-sdk/package.json "$version"
