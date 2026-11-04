#!/usr/bin/env bash
# Publishes the trees of dist/ (from build-dist.sh) as one commit each on the branch of the same name,
# tagged <branch>-v<version>. The cli package pins every platform package to its exact commit, so a
# shim never runs a binary of another release. Rerunning a failed release moves its tags.
# Usage: publish-branches.sh <git remote> <npm git spec of the remote, e.g. github:k18k/msecrets>
set -euo pipefail
cd "$(dirname "$0")/.."
remote=$1 spec=$2
version=$(cat VERSION)
source_commit=$(git rev-parse --short HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git_() { git -c user.name="${GIT_AUTHOR_NAME:-msecrets release}" -c user.email="${GIT_AUTHOR_EMAIL:-release@msecrets.invalid}" "$@"; }

# Commits dist/<name> on top of branch <name> (history is kept: older releases pin older commits).
publish() {
  local name=$1 tree=$work/$1
  if git ls-remote --exit-code --heads "$remote" "$name" >/dev/null; then
    git clone -q --depth 1 --branch "$name" "$remote" "$tree"
  else
    git init -q "$tree"
    git -C "$tree" checkout -q --orphan "$name"
  fi
  find "$tree" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  cp -R "dist/$name/." "$tree/"
  git -C "$tree" add -A
  git_ -C "$tree" commit -q --allow-empty -m "$name v$version (built from $source_commit)"
  git_ -C "$tree" tag -f "$name-v$version"
  git -C "$tree" push -q "$remote" "HEAD:refs/heads/$name" "+refs/tags/$name-v$version"
  git -C "$tree" rev-parse HEAD
}

optional="{}"
for dir in dist/cli-*-*; do
  name=${dir#dist/}
  sha=$(publish "$name")
  optional=$(node -e 'const [o, n, s] = process.argv.slice(1); console.log(JSON.stringify({ ...JSON.parse(o), ["@msecrets/" + n]: s }))' "$optional" "$name" "$spec#$sha")
done
node -e '
  const fs = require("node:fs");
  const pkg = JSON.parse(fs.readFileSync("dist/cli/package.json", "utf8"));
  pkg.optionalDependencies = JSON.parse(process.argv[1]);
  fs.writeFileSync("dist/cli/package.json", JSON.stringify(pkg, null, 2) + "\n");
' "$optional"
publish cli >/dev/null
publish ts-sdk >/dev/null
echo "Published cli, ts-sdk and $(ls -d dist/cli-*-* | wc -l) platform branches at v$version"
