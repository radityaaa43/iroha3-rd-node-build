#!/usr/bin/env bash
# Rebuild a node image WITHOUT the upstream sample files (ANALYST R15): /config/client.toml (the upstream sample account + private key)
# and the upstream example configs /opt/iroha/configs/soranexus/taira. A plain `RUN rm` would leave them in a lower layer (and in
# `docker pull`), so the filesystem is flattened into ONE layer (COPY --from=<image> / /) and the image metadata is re-applied.
# usage: build/strip-samples.sh <src-image> <dst-tag>
set -euo pipefail
src=${1:?usage: strip-samples.sh <src-image> <dst-tag>}; dst=${2:?usage: strip-samples.sh <src-image> <dst-tag>}
T=$(mktemp -d); trap 'find "$T" -delete' EXIT
docker image inspect "$src" --format '{{json .Config}}' > "$T/config.json"
python3 -I - "$src" "$T/config.json" > "$T/Dockerfile" <<'PY'
import json, sys
src, cfg = sys.argv[1], json.load(open(sys.argv[2]))
q = json.dumps
print(f"FROM {src} AS base")
print("USER 0")
print("RUN rm -f /config/client.toml && rm -rf /opt/iroha/configs/soranexus/taira /tmp/defaults")
print("FROM scratch")
print("COPY --from=base / /")
for e in cfg.get("Env") or []:
    k, v = e.split("=", 1); print(f"ENV {k}={q(v)}")
if cfg.get("WorkingDir"): print(f"WORKDIR {cfg['WorkingDir']}")
if cfg.get("User"): print(f"USER {cfg['User']}")
for p in (cfg.get("ExposedPorts") or {}): print(f"EXPOSE {p}")
if cfg.get("Entrypoint"): print(f"ENTRYPOINT {q(cfg['Entrypoint'])}")
if cfg.get("Cmd"): print(f"CMD {q(cfg['Cmd'])}")
PY
docker build -q -t "$dst" "$T" >/dev/null
echo "built $dst (flattened, samples removed)"
