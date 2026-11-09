#!/usr/bin/env bash
# Build/test the rd-dfabi driver as a member of the upstream workspace @ 071e281e, inside
# a resource-capped container. Used by CI and on an operator machine.
#
#   driver/build.sh test     cargo test --release -p rd-dfabi
#   driver/build.sh build    cargo build --release -p rd-dfabi, binary -> driver/dist/rd-dfabi
#
# Caps are mandatory, not tuning: an uncapped `cargo build -j10` of iroha_core hung a
# 12 vCPU / 22 GiB operator VM twice (2026-11-09). With a cgroup cap, running out of memory
# kills rustc inside the container, never the host. Raise MEM/JOBS only with known headroom.
set -euo pipefail

IROHA_COMMIT=071e281e778c5928cab4d6e007b7ddc9b050df27
WORK=${WORK:-$HOME/iroha3-build}   # persistent: /tmp is wiped on reboot
MEM=${MEM:-10g}
MEM_SWAP=${MEM_SWAP:-$MEM}          # = MEM: no swap inside the container
CPUS=${CPUS:-6}
JOBS=${JOBS:-1}
APP=$(cd "$(dirname "$0")" && pwd)

case "${1:-}" in
  test) CMD="cargo test --release -p rd-dfabi" ;;
  build) CMD="cargo build --release -p rd-dfabi" ;;
  *) echo "usage: $0 test|build" >&2; exit 2 ;;
esac

mkdir -p "$WORK/cargo-home" "$WORK/target"
if [ ! -d "$WORK/iroha/.git" ]; then
  git init -q "$WORK/iroha"
  git -C "$WORK/iroha" remote add origin https://github.com/hyperledger-iroha/iroha
  git -C "$WORK/iroha" fetch -q --depth 1 origin "$IROHA_COMMIT"
  git -C "$WORK/iroha" checkout -q FETCH_HEAD
  # Cargo fingerprints workspace crates by mtime. A fresh clone (every CI run) would be newer
  # than the cached target and rebuild all of upstream (~55 min); pin mtimes to the commit time.
  find "$WORK/iroha" -path "$WORK/iroha/.git" -prune -o -exec touch -h -d "@$(git -C "$WORK/iroha" log -1 --format=%ct)" {} +
fi
[ "$(git -C "$WORK/iroha" rev-parse HEAD)" = "$IROHA_COMMIT" ] || { echo "upstream is not $IROHA_COMMIT" >&2; exit 1; }
# Driver joins the workspace so it shares upstream's Cargo.lock and [patch] section.
git -C "$WORK/iroha" checkout -q -- Cargo.toml Cargo.lock
sed -i 's|^members = \[|members = [\n    "apps/rd-dfabi",|' "$WORK/iroha/Cargo.toml"
mkdir -p "$WORK/iroha/apps/rd-dfabi"

docker image inspect rd-dfabi-builder >/dev/null 2>&1 ||
  printf 'FROM rust:1.93.1-slim-bookworm\nRUN apt-get update -y && apt-get install -y build-essential mold pkg-config git && rm -rf /var/lib/apt/lists/*\n' |
  docker build -q -t rd-dfabi-builder -

nice -n 15 docker run --rm \
  --memory="$MEM" --memory-swap="$MEM_SWAP" --cpus="$CPUS" \
  --user "$(id -u):$(id -g)" \
  -e CARGO_HOME=/cargo-home -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS="$JOBS" \
  -v "$WORK/iroha:/src" -v "$APP:/src/apps/rd-dfabi:ro" \
  -v "$WORK/cargo-home:/cargo-home" -v "$WORK/target:/target" \
  -w /src rd-dfabi-builder mold --run sh -c "$CMD"

# Adding the member may only ADD lock entries (rd-dfabi itself); every upstream pin stays.
removed=$(git -C "$WORK/iroha" diff --numstat Cargo.lock | awk '{print $2}')
[ "${removed:-0}" = 0 ] || { echo "Cargo.lock changed upstream pins:" >&2; git -C "$WORK/iroha" diff Cargo.lock >&2; exit 1; }

if [ "$1" = build ]; then
  mkdir -p "$APP/dist"
  cp "$WORK/target/release/rd-dfabi" "$APP/dist/rd-dfabi"
  echo "built $APP/dist/rd-dfabi"
fi
