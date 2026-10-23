#!/usr/bin/env bash
# Build the Iroha 3 node image used by this network.
#
# Source commit: 071e281e (2026-09-16), the merge of upstream PR #5627
# "fix(kagami): add permissioned lane-0 validators" on branch `optimizations`.
# Why not the commit docs.iroha.tech pins (0010c5a7)? It does not compile:
# an unfinished SYSCALL_PROVE_EXECUTION -> SYSCALL_EXECUTION_SUMMARY rename
# breaks kotodama_lang and ivm. 071e281e descends from it with those fixed and
# keeps AtomicPrivateSettlementV1. Upstream `main` is months older; never use it.
#
# Usage: build/build-image.sh <iroha-source-dir> [image-tag]
set -euo pipefail

IROHA_COMMIT=071e281e778c5928cab4d6e007b7ddc9b050df27
SRC=${1:?usage: build-image.sh <iroha-source-dir> [image-tag]}
TAG=${2:-${TAG:-iroha3-rd:${IROHA_COMMIT:0:8}-stark}}

if [ "$(git -C "$SRC" rev-parse HEAD)" != "$IROHA_COMMIT" ]; then
  echo "source at $SRC is not $IROHA_COMMIT" >&2
  exit 1
fi

# zk-stark is required by the private-settlement (APS) prover/verifier.
# sorafs_external_software_signer is required by the upstream runtime stage.
DOCKER_BUILDKIT=1 docker build \
  --build-arg IROHA_RUST_BUILDER_IMAGE=rust:1.93.1-slim-bookworm \
  --build-arg IROHA_RUNTIME_IMAGE=debian:bookworm-slim \
  --build-arg PROFILE=release \
  --build-arg FEATURES="external-software-signer-bin,zk-stark" \
  --build-arg BINARIES="iroha3d iroha kagami sorafs_external_software_signer" \
  --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}" \
  --build-arg CONFIG_PROFILE=single \
  --build-arg IROHA_GIT_COMMIT_HASH="$IROHA_COMMIT" \
  --build-arg VERGEN_GIT_SHA="$IROHA_COMMIT" \
  -t "$TAG" "$SRC"
echo "built $TAG"
