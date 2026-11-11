#!/usr/bin/env bash
# Offline test (no docker, no network): no workflow may push to a tag that a live workload resolves by tag, and build-image must be manual-only.
# ci/live-tags.txt lists the live tags (one per line). A workflow may mention <repo>:<live-tag>-<suffix> (immutable) but never the plain live tag.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }; ok() { echo "ok:   $*"; }
while read -r tag; do
  [[ -z $tag || $tag == \#* ]] && continue
  bad=$(grep -nE "${tag//./\\.}([^-A-Za-z0-9_.]|$)" .github/workflows/*.yml || true)
  [[ -z $bad ]] && ok "no workflow names the plain live tag $tag" || fail "a workflow names the plain live tag $tag: $bad"
done < ci/live-tags.txt
grep -q 'github.sha' .github/workflows/build-image.yml && ok "build-image tags with the git sha (immutable)" || fail "build-image.yml does not use github.sha in its tag"
grep -qE '^on:' .github/workflows/build-image.yml && ! sed -n '/^on:/,/^permissions:/p' .github/workflows/build-image.yml | grep -qE '^  push:' && ok "build-image has no push trigger (manual dispatch only)" || fail "build-image.yml still triggers on push"
grep -q 'pull by digest' .github/workflows/build-image.yml && ok "build-image records the digest" || fail "build-image.yml records no digest"
if (( fails )); then echo "FAILED: $fails check(s)" >&2; exit 1; fi
echo "PASS"
