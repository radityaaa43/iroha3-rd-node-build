# Per-bank driver server mode (design, iroha3 PLAN S17, ARCHITECTURE-iroha3 row 10a)

Status: DESIGN ONLY. No code in this PR. Implementation follows as a separate PR (CI-only, RED test first) after this note is accepted.

## What and why
A thin HTTP wrapper over two EXISTING driver commands, running as a Deployment in each bank's own namespace, so that Lensa (relay + UI, no keys, no kubeconfig) can trigger the D-native DvP without any process holding two banks' keys (user decision "iroha dvp 1"):

| Route | Wraps | Meaning |
|---|---|---|
| `POST /settle-grant` | `dvp_native::settle_grant` (`driver/src/dvp_native.rs`, #14) | the bank's OWN account grants `CanExecuteSettlement` to the counterparty, bound to the exact DvP intent |
| `POST /dvp-native` | `dvp_native::dvp_native` | the bank's OWN account submits the `DvpIsi` (AllOrNothing, settlement id `dvp_<intent hex>`) |
| `GET /healthz` | - | liveness, no body from the chain |
| `POST /mint` | `mint::mint` (`driver/src/mint.rs`, S18, deviation K6, user word A 2026-11-12) | BI driver ONLY (config `mint_enabled = true`; every other driver answers 403 before reading the body): one native `Mint` of RD or DFABI to an account, signed by the BI client.toml key; body `{"to":"<ed0120..>","asset":"<Base58 id>","amount":"<n>"}`, amount a plain integer up to the auditor per-asset cap (`max_rd`, `max_dfabi`); the chain still requires `CanMintAssetWithDefinition` (BI, genesis S3) |
| `GET /tx/{hash}` | `tx_detail::fetch` (`driver/src/tx_detail.rs`, S18 window B, ANALYST Q16) | the transaction detail as the driver's OWN key may read it: ONE signed query (`get_transaction_details`), no transaction, no key material; hash = 64 hex; 200 `{"hash","transaction"}` or 400 bad hash / 405 / 502 with the upstream message unchanged (a bank driver cannot read another bank's detail and gets the upstream permission error). BI driver = read-all: gateway OPA, BI lens caller only, mTLS at window B; every call is logged |

Request body (JSON, public terms only): `{"counterparty"|"to": "<ed0120.. public key>", "give": "<Base58 asset id>:<n>", "take": "<Base58 asset id>:<n>", "intent": "<64 hex>"}`. Response: `{"tx_hash": "...", "status": "Applied"}` or `{"error": "<message>"}`. Asset ids are the Base58 definition ids (`RD_ID`, `DFABI_ID`); aliases do not parse (`iroha_data_model/src/asset/id.rs:314-344`).

## Conditions (ARCHITECTURE-iroha3 10a, kept verbatim in the implementation)
1. Runs only in that bank's namespace `rd-iroha3-<party>`; one Deployment, 1 replica, requests 50m/64Mi.
2. Mounts only `<party>.seed` + `<party>.note` of that bank (Secret `<party>-keys`, created by the bank with its own kubeconfig) and the public network files; NEVER the auditor key (`bi-auditor-key`), never another bank's keys.
   Precision (lead decision 2026-11-12, option a): the server signs with `Config.client_toml`, the bank's OWN client.toml, which is a second form of the same ed25519 key as `<party>.seed`. Secret `<party>-keys` therefore carries three files: `<party>.seed`, `<party>.note` and `client.toml`, all projected read-only at mode 0400. The bank derives `client.toml` in its own custody with `rd-dfabi keys client-toml <dir> <name> --torii <url> --chain <id> --network-id-file <path>` (reads `<dir>/<name>.seed`, writes `<dir>/client.toml` at 0600, never overwrites, never prints the key). Same namespace, same custody rule; still never the auditor key or another bank's key.
3. Exposes only the two commands above: no new chain logic, no generic "run any command", no config upload.
4. Reachable only through that bank's gateway (envoy + opa, mTLS) via a NetworkPolicy that admits the gateway pods of the same namespace on the server port and nothing else (default-deny stays).
5. Lensa calls it as a relay with public terms; it holds no key and no kubeconfig.

## Implementation sketch (for the follow-up PR)
- New subcommand `rd-dfabi server <config> --listen 0.0.0.0:8091` in `driver/src/main.rs`, handler in `driver/src/server.rs`, reusing `http::serve` (`driver/src/http.rs:36`, one request at a time: serialises submissions per bank, same intent as the auditor).
- The handler parses the JSON, calls the existing pure builders and `submit` of `dvp_native.rs`, and maps errors to `{"error": ...}` with HTTP 400 (bad input) or 502 (chain refusal). No secret is logged; the log line carries route, tx hash and status only.
- Own client: `client_toml` of the bank (own key, own Torii at `<party>-0.<party>.rd-iroha3-<party>.svc.cluster.local:8080`); fee from the bank's own account (`bounded_fee`), so each bank must hold XOR (the S5 genesis funds it; no engineer seeding).
- Tests (CI-only, `Compiling rd-dfabi` must show): request parsing and refusals (unknown route, bad JSON, missing field, wrong method), response shaping with the submit function injected, and "no key file name or key bytes in any response or log line".

## Open points (none blocks the design)
- Idempotence: the settlement id is one-shot per intent; a retry of `/dvp-native` for an applied intent is refused by the chain and returned as 502 with the chain message (no client-side dedupe).
- Authentication to the server port is the gateway's mTLS + opa policy; the server itself trusts the namespace (NetworkPolicy), like the auditor mode.
- Not covered here: S17 manifests (Deployment, Service, NetworkPolicy, Secret refs), which come as a render PR in `iroha3-rd-dfabi` with their own GO text after a driver image tag exists.

AFTER check: ARCHITECTURE-iroha3 10a (per-bank driver server mode = project client code, same class as `auditor.rs`) + iroha3 PLAN S17 "iroha dvp 1" — matches.
