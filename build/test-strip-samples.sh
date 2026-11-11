#!/usr/bin/env bash
# Test of build/strip-samples.sh on a tiny FIXTURE image (needs docker + debian:bookworm-slim; no network beyond that pull).
# The fixture has the upstream sample files in a LOWER layer; the stripped image must not contain them in ANY layer, and must keep
# ENV / USER / WORKDIR / ENTRYPOINT / CMD of the source image.
set -uo pipefail
cd "$(dirname "$0")/.."
S=build/strip-samples.sh
T=$(mktemp -d); trap 'docker rmi -f rd-strip-fixture:t rd-strip-out:t >/dev/null 2>&1; find "$T" -delete' EXIT
fails=0; fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }; ok() { echo "ok:   $*"; }
cat > "$T/Dockerfile" <<'DF'
FROM debian:bookworm-slim
RUN mkdir -p /config /opt/iroha/configs/soranexus/taira /opt/iroha/keep \
 && echo 'private_key = "SAMPLE"' > /config/client.toml && echo x > /opt/iroha/configs/soranexus/taira/config.toml \
 && echo keep > /opt/iroha/keep/tables.toml && echo peer > /config/peer.toml
ENV CONFIG_DIR=/config FIXTURE=1
WORKDIR /opt/iroha
USER 1001:1001
ENTRYPOINT ["sleep"]
CMD ["1"]
DF
docker build -q -t rd-strip-fixture:t "$T" >/dev/null || { echo "FAIL: fixture build" >&2; exit 1; }
out=$("$S" rd-strip-fixture:t rd-strip-out:t 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "strip-samples.sh builds the image" || { fail "rc=$rc $out"; exit 1; }
ls() { docker run --rm --entrypoint sh rd-strip-out:t -c "$1" 2>&1; }
[[ $(ls 'test -e /config/client.toml && echo present || echo gone') == gone ]] && ok "/config/client.toml is gone" || fail "client.toml still present"
[[ $(ls 'test -e /opt/iroha/configs/soranexus/taira && echo present || echo gone') == gone ]] && ok "taira examples are gone" || fail "taira examples still present"
[[ $(ls 'cat /opt/iroha/keep/tables.toml /config/peer.toml | tr "\n" " "') == "keep peer " ]] && ok "everything else is kept" || fail "kept files differ"
docker save rd-strip-out:t | tar -xO 2>/dev/null | grep -qa 'private_key = "SAMPLE"' && fail "sample text still inside a layer" || ok "sample text is in NO layer of the saved image"
for f in '{{.Config.Env}}' '{{.Config.User}}' '{{.Config.WorkingDir}}' '{{json .Config.Entrypoint}}' '{{json .Config.Cmd}}'; do
  a=$(docker image inspect rd-strip-fixture:t --format "$f"); b=$(docker image inspect rd-strip-out:t --format "$f")
  [[ $a == "$b" ]] && ok "metadata kept: $f" || fail "metadata $f: '$a' vs '$b'"
done
if (( fails )); then echo "FAILED: $fails check(s)" >&2; exit 1; fi
echo "PASS"
