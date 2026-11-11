#!/usr/bin/env bash
# Fail unless every named GHCR package has the visibility recorded in ci/package-visibility.expected (default for an unlisted package: private).
# usage: ci/check-package-visibility.sh <package>...   env: GH (default gh; needs GH_TOKEN with packages read), GITHUB_REPOSITORY_OWNER.
# Fail closed: a package whose visibility cannot be read is a failure. Never changes anything (read-only API call).
set -euo pipefail
cd "$(dirname "$0")/.."
(( $# >= 1 )) || { echo "usage: check-package-visibility.sh <package>..." >&2; exit 2; }
GH=${GH:-gh}; owner=${GITHUB_REPOSITORY_OWNER:-radityaaa43}; bad=0
for pkg in "$@"; do
  want=$(awk -v p="$pkg" '$1 == p { print $2 }' ci/package-visibility.expected)
  want=${want:-private}
  if ! got=$("$GH" api "/users/$owner/packages/container/$pkg" -q .visibility 2>&1); then
    echo "FAIL: cannot read the visibility of $pkg: $got" >&2; bad=1; continue
  fi
  if [[ $got == "$want" ]]; then echo "ok: $pkg is $got (expected $want)"
  elif [[ $got == public && $want == private ]]; then echo "FAIL: $pkg is public but must be private (no new public packages)" >&2; bad=1
  else echo "FAIL: $pkg visibility drift: is $got, recorded $want (record the change in ci/package-visibility.expected)" >&2; bad=1; fi
done
exit $bad
