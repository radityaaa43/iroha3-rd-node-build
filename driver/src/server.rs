//! Per-bank driver server mode (iroha3 PLAN S17, ARCHITECTURE-iroha3 row 10a, docs/server-mode.md).
//!
//! A thin HTTP wrapper over the two D-native commands of `dvp_native.rs`, running in ONE bank's namespace with that bank's own
//! client.toml (own key, own Torii). It exposes exactly: `GET /healthz`, `POST /settle-grant`, `POST /dvp-native`, `POST /mint` (403 unless the config sets `mint_enabled`: BI only), `POST /transfer` (RD/DFABI from the own account) and `GET /tx/{hash}` (a signed query with the own key), plus the APS endpoints `/aps/*` of `aps_http.rs`. Request bodies
//! carry public terms only; nothing secret is read from a request, written to a response or logged.

use std::sync::Mutex;

use eyre::Result;
use serde::Deserialize;

use crate::{
    aps_http, aps_real,
    config::Config,
    dvp_native, http,
    mint::{self, MintPolicy, MintTerms},
    tx_detail,
    balance, transfer,
};
use iroha::data_model::asset::AssetDefinitionId;

/// Public terms of one D-native DvP, in the calling bank's own give/take view (see `dvp_native.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    /// Counterparty public key (`ed0120...`); `to` is accepted for `/settle-grant`.
    #[serde(alias = "to")]
    pub counterparty: String,
    pub give: String,
    pub take: String,
    pub intent: String,
}

/// What the server does on the chain; the real one signs with the bank's own key, tests inject a fake.
pub trait Submitter {
    fn grant(&self, terms: &Terms) -> Result<String>;
    fn dvp(&self, terms: &Terms) -> Result<String>;
    /// `Some` only on the BI driver (config `mint_enabled`); `None` = every `/mint` is refused with 403.
    fn mint_policy(&self) -> Result<Option<MintPolicy>>;
    fn mint(&self, terms: &MintTerms) -> Result<String>;
    /// The assets `/transfer` may move (the config's RD and DFABI).
    fn transfer_assets(&self) -> Result<Vec<AssetDefinitionId>>;
    /// ONE native transfer from the own account (`transfer::transfer`); terms already checked.
    fn transfer(&self, terms: &MintTerms) -> Result<String>;
    /// Signed transaction-details query with the own key (`tx_detail::fetch`); `hash` is already validated.
    fn tx(&self, hash: &str) -> Result<String>;
    /// Signed query of the own account's balance of ONE asset (`balance::fetch`); `asset` is already validated.
    fn balance(&self, asset: &str) -> Result<String>;
}

/// Answer one request: `(HTTP status, JSON body)`. Pure apart from the injected submitter.
pub fn route(method: &str, path: &str, body: &str, submitter: &dyn Submitter) -> (u16, String) {
    let reply = |status: u16, value: serde_json::Value| (status, value.to_string());
    let error = |status: u16, message: String| reply(status, serde_json::json!({ "error": message }));
    match (method, path) {
        ("GET", "/healthz") => reply(200, serde_json::json!({})),
        (_, "/healthz") => error(405, "method not allowed".to_owned()),
        ("POST", "/settle-grant" | "/dvp-native") => {
            let terms: Terms = match serde_json::from_str(body) {
                Ok(terms) => terms,
                Err(e) => return error(400, format!("bad request body: {e}")),
            };
            if let Err(e) = dvp_native::check_terms(&terms.counterparty, &terms.give, &terms.take, &terms.intent) {
                return error(400, format!("{e:#}"));
            }
            let result = if path == "/settle-grant" { submitter.grant(&terms) } else { submitter.dvp(&terms) };
            match result {
                Ok(hash) => reply(200, serde_json::json!({ "tx_hash": hash, "status": "Applied" })),
                Err(e) => error(502, format!("{e:#}")),
            }
        }
        (_, "/settle-grant" | "/dvp-native") => error(405, "method not allowed".to_owned()),
        ("POST", "/mint") => match submitter.mint_policy() {
            Err(e) => error(502, format!("{e:#}")),
            Ok(None) => error(403, "mint is not enabled on this driver".to_owned()),
            Ok(Some(policy)) => {
                let terms: MintTerms = match serde_json::from_str(body) {
                    Ok(terms) => terms,
                    Err(e) => return error(400, format!("bad request body: {e}")),
                };
                if let Err(e) = mint::check_mint(&terms, &policy) {
                    return error(400, format!("{e:#}"));
                }
                match submitter.mint(&terms) {
                    Ok(hash) => reply(200, serde_json::json!({ "tx_hash": hash, "status": "Applied" })),
                    Err(e) => error(502, format!("{e:#}")),
                }
            }
        },
        (_, "/mint") => error(405, "method not allowed".to_owned()),
        ("POST", "/transfer") => {
            let terms: MintTerms = match serde_json::from_str(body) {
                Ok(terms) => terms,
                Err(e) => return error(400, format!("bad request body: {e}")),
            };
            match submitter.transfer_assets() {
                Err(e) => error(502, format!("{e:#}")),
                Ok(allowed) => match transfer::check_transfer(&terms, &allowed) {
                    Err(e) => error(400, format!("{e:#}")),
                    Ok(_) => match submitter.transfer(&terms) {
                        Ok(hash) => reply(200, serde_json::json!({ "tx_hash": hash, "status": "Applied" })),
                        Err(e) => error(502, format!("{e:#}")),
                    },
                },
            }
        }
        (_, "/transfer") => error(405, "method not allowed".to_owned()),
        ("GET", p) if p.starts_with("/tx/") => match tx_detail::check_hash(&p["/tx/".len()..]) {
            Err(e) => error(400, format!("{e:#}")),
            Ok(hash) => match submitter.tx(&hash) {
                Ok(body) => (200, body),
                Err(e) => error(502, format!("{e:#}")),
            },
        },
        (_, p) if p.starts_with("/tx/") => error(405, "method not allowed".to_owned()),
        ("GET", p) if p == "/balance" || p.starts_with("/balance?") => match balance::asset_param(p).and_then(|a| balance::check_asset(&a).map(|_| a)) {
            Err(e) => error(400, format!("{e:#}")),
            Ok(asset) => match submitter.balance(&asset) {
                Ok(body) => (200, body),
                Err(e) => error(502, format!("{e:#}")),
            },
        },
        (_, p) if p == "/balance" || p.starts_with("/balance?") => error(405, "method not allowed".to_owned()),
        _ => error(404, "not found".to_owned()),
    }
}

/// `/aps/*` goes to the APS handlers (`aps_http`), everything else to `route`.
fn dispatch(method: &str, path: &str, body: &str, submitter: &dyn Submitter, aps: &aps_http::Aps) -> (u16, String) {
    if path.starts_with("/aps/") { aps.route(method, path, body) } else { route(method, path, body, submitter) }
}

struct Real {
    // One submission at a time per bank (serialised like the auditor mode); `Mutex` keeps `Real: Sync`.
    cfg: Mutex<Config>,
}

impl Submitter for Real {
    fn grant(&self, terms: &Terms) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        dvp_native::settle_grant(&cfg, &terms.counterparty, &terms.give, &terms.take, &terms.intent)
    }

    fn dvp(&self, terms: &Terms) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        dvp_native::dvp_native(&cfg, &terms.counterparty, &terms.give, &terms.take, &terms.intent)
    }

    fn mint_policy(&self) -> Result<Option<MintPolicy>> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        mint::policy_of(&cfg)
    }

    fn mint(&self, terms: &MintTerms) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        mint::mint(&cfg, terms)
    }

    fn transfer_assets(&self) -> Result<Vec<AssetDefinitionId>> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        transfer::allowed(&cfg)
    }

    fn transfer(&self, terms: &MintTerms) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        transfer::transfer(&cfg, terms)
    }

    fn tx(&self, hash: &str) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        tx_detail::fetch(&cfg, hash)
    }

    fn balance(&self, asset: &str) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        balance::fetch(&cfg, asset)
    }
}

/// `rd-dfabi server <config> --listen <addr>`.
pub fn run(cfg: Config, listen: &str) -> Result<()> {
    let peer = aps_http::RealPeer { tls: cfg.tls.clone() };
    let aps_cfg = cfg.aps.clone();
    let real = Real { cfg: Mutex::new(cfg) };
    let backend = aps_real::RealBackend::new(&real.cfg);
    let aps = aps_http::Aps::new(&backend, &peer, aps_cfg);
    // One thread per connection: a bank's forwarded `/aps/submit` waits on BI while BI calls back into the same bank.
    http::serve_threaded(listen, |method, path, body| {
        let (status, response) = dispatch(method, path, body, &real, &aps);
        eprintln!("{method} {path} -> {status}");
        (status, response)
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::config::signing_key;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<(&'static str, Terms)>>,
        mints: RefCell<Vec<MintTerms>>,
        txs: RefCell<Vec<String>>,
        balances: RefCell<Vec<String>>,
        transfers: RefCell<Vec<MintTerms>>,
        /// `Some(message)` = the upstream refuses the balance query with this message.
        balance_refusal: Option<String>,
        /// `Some(message)` = the upstream refuses a transaction-details query with this message.
        tx_refusal: Option<String>,
        /// `Some` = this is a BI driver with mint enabled.
        policy: Option<MintPolicy>,
        fail: bool,
    }

    impl Submitter for Fake {
        fn grant(&self, terms: &Terms) -> Result<String> {
            self.calls.borrow_mut().push(("grant", terms.clone()));
            if self.fail { Err(eyre::eyre!("chain refused")) } else { Ok("txh-grant".to_owned()) }
        }

        fn dvp(&self, terms: &Terms) -> Result<String> {
            self.calls.borrow_mut().push(("dvp", terms.clone()));
            if self.fail { Err(eyre::eyre!("chain refused")) } else { Ok("txh-dvp".to_owned()) }
        }

        fn mint_policy(&self) -> Result<Option<MintPolicy>> {
            Ok(self.policy.clone())
        }

        fn mint(&self, terms: &MintTerms) -> Result<String> {
            self.mints.borrow_mut().push(terms.clone());
            if self.fail { Err(eyre::eyre!("chain refused")) } else { Ok("txh-mint".to_owned()) }
        }

        fn transfer_assets(&self) -> Result<Vec<AssetDefinitionId>> {
            Ok(vec![asset(1).parse().unwrap(), asset(2).parse().unwrap()])
        }

        fn transfer(&self, terms: &MintTerms) -> Result<String> {
            self.transfers.borrow_mut().push(terms.clone());
            if self.fail { Err(eyre::eyre!("chain refused")) } else { Ok("txh-transfer".to_owned()) }
        }

        fn balance(&self, asset: &str) -> Result<String> {
            self.balances.borrow_mut().push(asset.to_owned());
            match &self.balance_refusal {
                Some(message) => Err(eyre::eyre!("{message}")),
                None => Ok(format!(r#"{{"account":"own","asset":"{asset}","balance":{{"value":"5"}}}}"#)),
            }
        }

        fn tx(&self, hash: &str) -> Result<String> {
            self.txs.borrow_mut().push(hash.to_owned());
            match &self.tx_refusal {
                Some(message) => Err(eyre::eyre!("{message}")),
                None => Ok(format!(r#"{{"hash":"{hash}","transaction":{{"result":"Ok"}}}}"#)),
            }
        }
    }

    fn bi() -> Fake {
        Fake { policy: Some(MintPolicy { allowed: vec![(asset(1).parse().unwrap(), 1000)] }), ..Fake::default() }
    }

    fn mint_body(amount: &str) -> String {
        format!(r#"{{"to":"{}","asset":"{}","amount":"{amount}"}}"#, account(), asset(1))
    }

    fn asset(n: u8) -> String {
        AssetDefinitionId::from_uuid_bytes([n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]).unwrap().to_string()
    }

    fn account() -> String {
        signing_key(&[7; 32]).public_key().to_string()
    }

    fn body(key: &str) -> String {
        format!(r#"{{"{key}":"{}","give":"{}:5","take":"{}:10","intent":"{}"}}"#, account(), asset(1), asset(2), "ab".repeat(32))
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    fn transfer_body(asset_n: u8, amount: &str) -> String {
        format!(r#"{{"to":"{}","asset":"{}","amount":"{amount}"}}"#, account(), asset(asset_n))
    }

    #[test]
    fn a_valid_transfer_of_a_configured_asset_is_submitted_once() {
        let fake = Fake::default();
        let (status, response) = route("POST", "/transfer", &transfer_body(1, "7"), &fake);
        assert_eq!((status, json(&response)), (200, serde_json::json!({"tx_hash": "txh-transfer", "status": "Applied"})));
        assert_eq!(*fake.transfers.borrow(), vec![MintTerms { to: account(), asset: asset(1), amount: "7".to_owned() }]);
    }

    #[test]
    fn a_transfer_of_another_asset_a_zero_amount_or_garbage_is_400_and_a_get_is_405() {
        let fake = Fake::default();
        let unknown = transfer_body(1, "7").replace('}', r#","from":"x"}"#);
        for bad in [transfer_body(3, "7"), transfer_body(1, "0"), transfer_body(1, "-1"), "{}".to_owned(), "x".to_owned(), unknown] {
            assert_eq!(route("POST", "/transfer", &bad, &fake).0, 400, "{bad}");
        }
        assert_eq!(route("GET", "/transfer", "", &fake).0, 405);
        assert!(fake.transfers.borrow().is_empty());
    }

    #[test]
    fn a_refused_transfer_is_502() {
        let fake = Fake { fail: true, ..Fake::default() };
        assert_eq!(route("POST", "/transfer", &transfer_body(1, "7"), &fake).0, 502);
    }

    #[test]
    fn healthz_answers_without_touching_the_chain() {
        let fake = Fake::default();
        let (status, response) = route("GET", "/healthz", "", &fake);
        assert_eq!((status, json(&response)), (200, serde_json::json!({})));
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn unknown_route_is_404_and_a_wrong_method_is_405() {
        let fake = Fake::default();
        assert_eq!(route("GET", "/keys", "", &fake).0, 404);
        assert_eq!(route("POST", "/approve", "{}", &fake).0, 404);
        assert_eq!(route("GET", "/dvp-native", "", &fake).0, 405);
        assert_eq!(route("GET", "/settle-grant", "", &fake).0, 405);
        assert_eq!(route("POST", "/healthz", "{}", &fake).0, 405);
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn malformed_json_missing_and_unknown_fields_are_400_and_never_submit() {
        let fake = Fake::default();
        let unknown = body("counterparty").replace('}', r#","command":"id"}"#);
        for bad in ["", "not json", "{}", r#"{"counterparty":"x"}"#, unknown.as_str()] {
            let (status, response) = route("POST", "/dvp-native", bad, &fake);
            assert_eq!(status, 400, "{bad:?}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn invalid_terms_are_400_and_never_submit() {
        let fake = Fake::default();
        let ok = body("counterparty");
        let cases = [
            ok.replace(&"ab".repeat(32), "abcd"),
            ok.replace(":5\"", ":0\""),
            ok.replace(&asset(2), &asset(1)),
            ok.replace(&account(), "not-a-key"),
        ];
        for bad in cases {
            assert_eq!(route("POST", "/dvp-native", &bad, &fake).0, 400, "{bad}");
            assert_eq!(route("POST", "/settle-grant", &bad, &fake).0, 400, "{bad}");
        }
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn valid_grant_and_dvp_are_submitted_with_exactly_the_given_terms() {
        let fake = Fake::default();
        let (status, response) = route("POST", "/settle-grant", &body("to"), &fake);
        assert_eq!((status, json(&response)), (200, serde_json::json!({"tx_hash": "txh-grant", "status": "Applied"})));
        let (status, response) = route("POST", "/dvp-native", &body("counterparty"), &fake);
        assert_eq!((status, json(&response)), (200, serde_json::json!({"tx_hash": "txh-dvp", "status": "Applied"})));
        let terms = Terms { counterparty: account(), give: format!("{}:5", asset(1)), take: format!("{}:10", asset(2)), intent: "ab".repeat(32) };
        assert_eq!(*fake.calls.borrow(), vec![("grant", terms.clone()), ("dvp", terms)]);
    }

    #[test]
    fn a_chain_refusal_is_502_with_only_an_error_field() {
        let fake = Fake { fail: true, ..Fake::default() };
        let (status, response) = route("POST", "/dvp-native", &body("counterparty"), &fake);
        assert_eq!(status, 502);
        assert_eq!(json(&response), serde_json::json!({"error": "chain refused"}));
    }

    #[test]
    fn no_response_names_a_key_file_or_echoes_the_request_terms() {
        let fake = Fake::default();
        let failing = Fake { fail: true, ..Fake::default() };
        let mut all = vec![];
        for (path, request) in [("/healthz", String::new()), ("/settle-grant", body("to")), ("/dvp-native", body("counterparty")), ("/nope", String::new()), ("/dvp-native", "garbage".to_owned())] {
            all.push(route("POST", path, &request, &fake).1);
            all.push(route("POST", path, &request, &failing).1);
        }
        for response in all {
            assert!(!response.contains(".seed") && !response.contains(".note") && !response.contains("client.toml"), "{response}");
            assert!(!response.contains(&"ab".repeat(32)), "the intent must not be echoed: {response}");
        }
    }

    #[test]
    fn mint_is_403_on_a_driver_without_mint_enabled_and_never_reaches_the_chain() {
        let bank = Fake::default();
        for request in [mint_body("5"), String::new(), "garbage".to_owned()] {
            let (status, response) = route("POST", "/mint", &request, &bank);
            assert_eq!(status, 403, "{request:?}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(bank.mints.borrow().is_empty() && bank.calls.borrow().is_empty());
    }

    #[test]
    fn mint_is_405_on_a_wrong_method_and_healthz_still_works_on_bi() {
        let bi = bi();
        assert_eq!(route("GET", "/mint", "", &bi).0, 405);
        assert_eq!(route("GET", "/healthz", "", &bi).0, 200);
        assert!(bi.mints.borrow().is_empty());
    }

    #[test]
    fn mint_bad_bodies_and_terms_are_400_and_never_submit() {
        let bi = bi();
        let unknown = mint_body("5").replace('}', r#","from":"x"}"#);
        let ok = mint_body("5");
        let cases = [
            String::new(),
            "not json".to_owned(),
            "{}".to_owned(),
            unknown,
            mint_body("0"),
            mint_body("1001"),
            mint_body("abc"),
            ok.replace(&asset(1), &asset(9)),
            ok.replace(&account(), "not-a-key"),
        ];
        for bad in cases {
            let (status, response) = route("POST", "/mint", &bad, &bi);
            assert_eq!(status, 400, "{bad:?}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(bi.mints.borrow().is_empty());
    }

    #[test]
    fn a_valid_mint_is_submitted_once_with_exactly_the_given_terms() {
        let bi = bi();
        let (status, response) = route("POST", "/mint", &mint_body("250"), &bi);
        assert_eq!((status, json(&response)), (200, serde_json::json!({"tx_hash": "txh-mint", "status": "Applied"})));
        assert_eq!(*bi.mints.borrow(), vec![MintTerms { to: account(), asset: asset(1), amount: "250".to_owned() }]);
    }

    #[test]
    fn a_mint_chain_refusal_is_502_with_only_an_error_field() {
        let bi = Fake { fail: true, ..bi() };
        let (status, response) = route("POST", "/mint", &mint_body("5"), &bi);
        assert_eq!(status, 502);
        assert_eq!(json(&response), serde_json::json!({"error": "chain refused"}));
    }

    #[test]
    fn tx_detail_is_a_get_of_a_valid_hash_and_returns_exactly_what_the_query_returned() {
        let fake = Fake::default();
        let hash = "ab".repeat(32);
        let (status, response) = route("GET", &format!("/tx/{hash}"), "", &fake);
        assert_eq!((status, json(&response)), (200, serde_json::json!({"hash": hash, "transaction": {"result": "Ok"}})));
        assert_eq!(*fake.txs.borrow(), vec![hash.clone()]);
        // an upper-case hash is lowered before the query
        let (status, _) = route("GET", &format!("/tx/{}", hash.to_uppercase()), "", &fake);
        assert_eq!(status, 200);
        assert_eq!(fake.txs.borrow()[1], hash);
    }

    #[test]
    fn tx_detail_bad_hashes_are_400_and_never_query() {
        let fake = Fake::default();
        for bad in ["/tx/", "/tx/abcd", "/tx/zz", &format!("/tx/{}", "ab".repeat(33)), &format!("/tx/../{}", "ab".repeat(30)), &format!("/tx/{}?x=1", "ab".repeat(32))] {
            let (status, response) = route("GET", bad, "", &fake);
            assert_eq!(status, 400, "{bad}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(fake.txs.borrow().is_empty());
    }

    #[test]
    fn tx_detail_other_methods_are_405_and_never_query() {
        let fake = Fake::default();
        let path = format!("/tx/{}", "ab".repeat(32));
        for method in ["POST", "PUT", "DELETE"] {
            assert_eq!(route(method, &path, "{}", &fake).0, 405, "{method}");
        }
        assert!(fake.txs.borrow().is_empty());
    }

    #[test]
    fn an_upstream_permission_error_is_passed_through_not_turned_into_a_filtered_success() {
        let message = "query_validation_failed: account is not permitted to read this transaction";
        let fake = Fake { tx_refusal: Some(message.to_owned()), ..Fake::default() };
        let (status, response) = route("GET", &format!("/tx/{}", "ab".repeat(32)), "", &fake);
        assert_eq!(status, 502);
        assert_eq!(json(&response), serde_json::json!({"error": message}));
    }

    #[test]
    fn balance_is_a_get_of_one_valid_asset_and_asks_for_the_own_account_only() {
        let fake = Fake::default();
        let (status, response) = route("GET", "/balance?asset=7onbjg2gRXveoAAUFsohCZyGW98t", "", &fake);
        assert_eq!(status, 200);
        assert_eq!(json(&response)["asset"], "7onbjg2gRXveoAAUFsohCZyGW98t");
        // the submitter is only ever given the asset: no request field can name another account
        assert_eq!(*fake.balances.borrow(), vec!["7onbjg2gRXveoAAUFsohCZyGW98t".to_owned()]);
    }

    #[test]
    fn balance_bad_or_extra_parameters_are_400_and_never_query() {
        let fake = Fake::default();
        for bad in [
            "/balance",
            "/balance?asset=",
            "/balance?asset=rd%23wonderland.ds-rd",
            "/balance?account=ed0120aa&asset=7onbjg2gRXveoAAUFsohCZyGW98t",
            "/balance?asset=7onbjg2gRXveoAAUFsohCZyGW98t&asset=4mBWK1JCwQdHLDPpuVKc56eLsXka",
            "/balance?asset=../x",
        ] {
            let (status, response) = route("GET", bad, "", &fake);
            assert_eq!(status, 400, "{bad}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(fake.balances.borrow().is_empty());
    }

    #[test]
    fn balance_other_methods_are_405_and_never_query() {
        let fake = Fake::default();
        for method in ["POST", "PUT", "DELETE"] {
            assert_eq!(route(method, "/balance?asset=7onbjg2gRXveoAAUFsohCZyGW98t", "{}", &fake).0, 405, "{method}");
        }
        assert!(fake.balances.borrow().is_empty());
    }

    #[test]
    fn a_balance_upstream_permission_error_is_passed_through_unchanged_as_502() {
        let message = "query_validation_failed: account is not permitted to read this dataspace";
        let fake = Fake { balance_refusal: Some(message.to_owned()), ..Fake::default() };
        let (status, response) = route("GET", "/balance?asset=7onbjg2gRXveoAAUFsohCZyGW98t", "", &fake);
        assert_eq!(status, 502);
        assert_eq!(json(&response), serde_json::json!({"error": message}));
    }

    #[test]
    fn aps_paths_go_to_the_aps_handlers_and_everything_else_stays_with_the_submitter() {
        use crate::aps_http::{Aps, testkit::{FakeBackend, FakePeer}};
        let (backend, peer) = (FakeBackend::default(), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, crate::config::ApsConfig::default());
        let fake = Fake::default();
        assert_eq!(dispatch("GET", "/aps/wallet", "", &fake, &aps).0, 200);
        assert_eq!(dispatch("POST", "/aps/wallet", "", &fake, &aps).0, 405);
        assert_eq!(dispatch("GET", "/aps/nope", "", &fake, &aps).0, 404);
        assert_eq!(dispatch("GET", "/healthz", "", &fake, &aps).0, 200);
        assert_eq!(dispatch("GET", "/nope", "", &fake, &aps).0, 404);
        assert_eq!(dispatch("POST", "/settle-grant", &body("to"), &fake, &aps).0, 200);
        assert_eq!(fake.calls.borrow().len(), 1, "only the non-APS grant reached the submitter");
    }

    /// Live: a submit takes 100-200 s and kubelet kills the pod when `/healthz` stays unanswered for about 365 s.
    #[test]
    fn healthz_answers_while_a_submit_is_in_progress() {
        use crate::aps_http::{
            Aps,
            testkit::{FakeBackend, FakePeer, account},
        };
        use std::time::{Duration, Instant};
        let backend: &'static FakeBackend = Box::leak(Box::new(FakeBackend { me: account(7), settle_delay: Duration::from_millis(600), ..FakeBackend::default() }));
        let peer: &'static FakePeer = Box::leak(Box::new(FakePeer::standard()));
        let cfg = crate::config::ApsConfig {
            coordinator: true,
            peers: std::collections::BTreeMap::from([
                (account(8), "https://gateway.rd-iroha3-bank-a.svc.cluster.local:8443".to_owned()),
                (account(9), "https://gateway.rd-iroha3-bank-b.svc.cluster.local:8443".to_owned()),
            ]),
            ..Default::default()
        };
        let aps: &'static Aps<'static> = Box::leak(Box::new(Aps::new(backend, peer, cfg)));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || http::serve_listener_threaded(&listener, &|method: &str, path: &str, body: &str| dispatch(method, path, body, &Fake::default(), aps)));
        let submit = serde_json::json!({ "kind": "pay", "intent": "ab".repeat(32), "asset": "rd", "from": account(8), "to": account(9), "amount": "5" }).to_string();
        let started = Instant::now();
        let waiting = {
            let addr = addr.clone();
            std::thread::spawn(move || http::request_with(&addr, "POST", "/aps/submit", &submit, None, Duration::from_secs(10)))
        };
        std::thread::sleep(Duration::from_millis(100));
        let (status, _) = http::request_with(&addr, "GET", "/healthz", "", None, Duration::from_secs(5)).unwrap();
        assert_eq!(status, 200);
        assert!(started.elapsed() < Duration::from_millis(500), "healthz waited for the submit: {:?}", started.elapsed());
        let (status, response) = waiting.join().unwrap().unwrap();
        assert_eq!((status, json(&response)["outcome"].as_str()), (200, Some("finalized")));
        assert!(started.elapsed() >= Duration::from_millis(600), "the submit really was in progress");
    }
}
