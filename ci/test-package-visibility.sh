#!/usr/bin/env bash
# Offline test of ci/check-package-visibility.sh with a STUB gh (no network). Needs bash.
set -uo pipefail
cd "$(dirname "$0")/.."
C=ci/check-package-visibility.sh
T=$(mktemp -d); trap 'find "$T" -delete' EXIT
fails=0; fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }; ok() { echo "ok:   $*"; }
mkdir "$T/bin"
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh api /users/<owner>/packages/container/<name> -q .visibility : answer from $STUB_VIS_<name with - as _>, or fail like a 404
n=${2##*/}; v="STUB_VIS_${n//-/_}"
[[ -n ${!v:-} ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
echo "${!v}"
STUB
chmod +x "$T/bin/gh"; export GH="$T/bin/gh" GITHUB_REPOSITORY_OWNER=radityaaa43
run() { out=$("$C" "$@" 2>&1); rc=$?; }
export STUB_VIS_iroha3_rd_node=public STUB_VIS_iroha3_rd_driver=public STUB_VIS_iroha3_rd_new=private
run iroha3-rd-node iroha3-rd-driver; [[ $rc -eq 0 ]] && ok "recorded public packages match" || fail "recorded: rc=$rc $out"
run iroha3-rd-new; [[ $rc -eq 0 ]] && ok "an unlisted package that is private passes" || fail "new private: rc=$rc $out"
STUB_VIS_iroha3_rd_new=public run iroha3-rd-new; [[ $rc -ne 0 && $out == *"must be private"* ]] && ok "an unlisted package that is public FAILS" || fail "new public: rc=$rc $out"
STUB_VIS_iroha3_rd_driver=private run iroha3-rd-driver; [[ $rc -ne 0 && $out == *"drift"* ]] && ok "a recorded-public package that changed FAILS (re-record it)" || fail "drift: rc=$rc $out"
run iroha3-rd-missing; [[ $rc -ne 0 && $out == *"cannot read"* ]] && ok "an unreadable package FAILS (fail closed)" || fail "unreadable: rc=$rc $out"
run; [[ $rc -eq 2 && $out == *usage* ]] && ok "no argument: usage, exit 2" || fail "usage: rc=$rc $out"
if (( fails )); then echo "FAILED: $fails check(s)" >&2; exit 1; fi
echo "PASS"
