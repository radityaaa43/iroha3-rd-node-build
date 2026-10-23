# iroha3-rd-node-build

Public build of the Hyperledger Iroha 3 node image used by the RD/DFABI PoC.
This repo only compiles upstream open-source code. It holds no keys, no
cluster access, and no self-hosted runners.

- Source: [`hyperledger-iroha/iroha`](https://github.com/hyperledger-iroha/iroha) @ `071e281e778c5928cab4d6e007b7ddc9b050df27`
- Features: `external-software-signer-bin,zk-stark`
- Binaries: `iroha3d`, `iroha`, `kagami`, `sorafs_external_software_signer`
- Image: `ghcr.io/radityaaa43/iroha3-rd-node:071e281e-stark`

Build locally: `build/build-image.sh <iroha-source-at-071e281e> [tag]`.
CI: `.github/workflows/build-image.yml` (GitHub-hosted runner).
