//! Per-bank driver server mode (iroha3 PLAN S17, ARCHITECTURE-iroha3 row 10a, docs/server-mode.md).
//!
//! A thin HTTP wrapper over the two D-native commands of `dvp_native.rs`, running in ONE bank's namespace with that bank's own
//! client.toml (own key, own Torii). It exposes exactly: `GET /healthz`, `POST /settle-grant`, `POST /dvp-native`, and `POST /mint` (403 unless the config sets `mint_enabled`: BI only). Request bodies
//! carry public terms only; nothing secret is read from a request, written to a response or logged.

use std::sync::Mutex;

use eyre::Result;
use serde::Deserialize;

use crate::{
    config::Config,
    dvp_native, http,
    mint::{self, MintPolicy, MintTerms},
};

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
        _ => error(404, "not found".to_owned()),
    }
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
}

/// `rd-dfabi server <config> --listen <addr>`.
pub fn run(cfg: Config, listen: &str) -> Result<()> {
    let real = Real { cfg: Mutex::new(cfg) };
    http::serve(listen, |method, path, body| {
        let (status, response) = route(method, path, body, &real);
        eprintln!("{method} {path} -> {status}");
        (status, response)
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use iroha::data_model::asset::AssetDefinitionId;

    use super::*;
    use crate::config::signing_key;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<(&'static str, Terms)>>,
        mints: RefCell<Vec<MintTerms>>,
        txs: RefCell<Vec<String>>,
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
}
