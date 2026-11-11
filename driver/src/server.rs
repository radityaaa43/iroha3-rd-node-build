//! Per-bank driver server mode (iroha3 PLAN S17, ARCHITECTURE-iroha3 row 10a, docs/server-mode.md).
//!
//! A thin HTTP wrapper over the two D-native commands of `dvp_native.rs`, running in ONE bank's namespace with that bank's own
//! client.toml (own key, own Torii). It exposes exactly: `GET /healthz`, `POST /settle-grant`, `POST /dvp-native`. Request bodies
//! carry public terms only; nothing secret is read from a request, written to a response or logged.

use std::sync::Mutex;

use eyre::Result;
use serde::Deserialize;

use crate::{config::Config, dvp_native, http};

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
}
