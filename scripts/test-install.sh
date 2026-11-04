#!/usr/bin/env bash
# End-to-end install test: publishes dist/ (from build-dist.sh) to a local bare repository and
# installs from it the way users install from GitHub.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD version=$(cat VERSION)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo=$tmp/repo.git
git init -q --bare "$repo"
git push -q "$repo" HEAD:refs/heads/master # npm resolves refs against HEAD
scripts/publish-branches.sh "$repo" "git+file://$repo"

echo "CLI: npm install -g github:…#cli"
npm install -g --silent --allow-git=all --prefix "$tmp/global" "git+file://$repo#cli"
installed=$(ls "$tmp/global/lib/node_modules/@msecrets/cli/node_modules/@msecrets")
[ "$installed" = "cli-$(node -p 'process.platform + "-" + process.arch')" ] || { echo "expected only the host platform package, got: $installed"; exit 1; }
[ "$("$tmp/global/bin/msecrets" --version)" = "msecrets $version" ]

echo "CLI without --allow-git=all explains how to fix the install"
npm install -g --silent --allow-git=root --prefix "$tmp/root-only" "git+file://$repo#cli"
if "$tmp/root-only/bin/msecrets" --version 2>"$tmp/err"; then echo "expected a failure"; exit 1; fi
grep -q -- "--allow-git=all" "$tmp/err"

echo "SDK: npm install github:…#ts-sdk, ESM and CommonJS"
mkdir "$tmp/app"
cp sdk/test/fixtures/app.ms.json sdk/test/fixtures/developer.identity.txt "$tmp/app/"
cd "$tmp/app"
npm init -y >/dev/null
npm install --silent --allow-git=root "git+file://$repo#ts-sdk"
export MSECRETS_IDENTITY_FILE=$tmp/app/developer.identity.txt MSECRETS_CONFIG_DIR=$tmp/config
cat > check.mjs <<'JS'
import { readFileSync } from "node:fs";
import { createClient } from "@msecrets/ts-sdk";
const secrets = createClient(JSON.parse(readFileSync("app.ms.json", "utf8")));
if (!Object.keys(secrets).length) throw new Error("no secrets");
JS
cat > check.cjs <<'JS'
const { createClient } = require("@msecrets/ts-sdk");
const secrets = createClient(require("./app.ms.json"));
if (!Object.keys(secrets).length) throw new Error("no secrets");
JS
node check.mjs
node check.cjs
cd "$root"
echo "Install test passed"
