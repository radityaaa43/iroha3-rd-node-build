/// Fakes for the APS HTTP tests (this file's and `server.rs`'s): no chain, no proving, no network.
#[cfg(test)]
pub(crate) mod testkit {
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

    /// A distinct valid account public key per `n`.
    pub(crate) fn account(n: u8) -> String {
        crate::config::signing_key(&[n; 32]).public_key().to_string()
    }

    /// 32 bytes of `n`, as 64 lowercase hex characters.
    pub(crate) fn id(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    #[derive(Default)]
    pub(crate) struct FakeBackend {
        /// The own account key `own_key` answers.
        pub me: String,
        /// Every call that reached the backend, in order (`own_key` is not listed).
        pub calls: Mutex<Vec<&'static str>>,
        /// `Some(message)` = address, sponsor_output, begin_bundle, prove_leg, settle and wallet all fail with it.
        pub error: Option<String>,
        /// `settle` answers "aborted".
        pub aborts: bool,
        pub settle_delay: Duration,
        pub active: AtomicUsize,
        pub max_active: AtomicUsize,
    }

    impl FakeBackend {
        fn note(&self, call: &'static str) -> Result<()> {
            self.calls.lock().unwrap().push(call);
            match &self.error {
                Some(message) => Err(eyre::eyre!("{message}")),
                None => Ok(()),
            }
        }
    }

    fn key() -> OutputKey {
        OutputKey { authority: id(0x11), view_public: id(0x22), authorization: "abcd".to_owned() }
    }

    impl ApsBackend for FakeBackend {
        fn own_key(&self) -> Result<String> {
            Ok(self.me.clone())
        }

        fn address(&self, _req: &AddressReq) -> Result<OutputKey> {
            self.note("address")?;
            Ok(key())
        }

        fn sponsor_output(&self, _ctx: &AddressReq, active: bool) -> Result<SponsorOutput> {
            self.note("sponsor_output")?;
            let key = key();
            Ok(SponsorOutput { authority: key.authority, view_public: key.view_public, authorization: key.authorization, active })
        }

        fn begin_bundle(&self) -> Result<BundleCtx> {
            self.note("begin_bundle")?;
            let leg = |n: u8| LegCtx { pool_id: id(n), route: "0a".to_owned(), authority_digest: id(0xdd) };
            Ok(BundleCtx { bundle_id: id(0xbb), manifest: "abcd".to_owned(), salt: id(0xcc), expiry_height: 10, network_id: "ee".to_owned(), legs: [leg(1), leg(2)] })
        }

        fn prove_leg(&self, _req: &LegReq) -> Result<String> {
            self.note("prove")?;
            Ok("beef".to_owned())
        }

        fn settle(&self, _bundle: &BundleCtx, _prepared: &[String; 2]) -> Result<Option<Settled>> {
            let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.settle_delay);
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.note("settle")?;
            Ok(if self.aborts { None } else { Some(Settled { carrier_tx: "txh".to_owned(), height: 42 }) })
        }

        fn wallet(&self) -> Result<serde_json::Value> {
            self.note("wallet")?;
            Ok(serde_json::json!({ "party": "fake", "balances": { "rd": "5", "dfabi": "6" }, "items": [] }))
        }
    }

    type Answer = Box<dyn Fn(&str, &str, &str) -> Result<(u16, String)> + Send + Sync>;

    pub(crate) struct FakePeer {
        /// `(target, method, path, body)` of every call.
        pub calls: Mutex<Vec<(String, String, String, String)>>,
        answer: Answer,
    }

    impl FakePeer {
        /// `answer(target, path, body)`.
        pub(crate) fn with(answer: impl Fn(&str, &str, &str) -> Result<(u16, String)> + Send + Sync + 'static) -> Self {
            Self { calls: Mutex::default(), answer: Box::new(answer) }
        }

        /// A healthy party: signs addresses, proves legs, finalizes submits.
        pub(crate) fn standard() -> Self {
            Self::with(|_, path, _| match path {
                "/aps/address" => Ok((200, serde_json::json!({ "authority": id(0x33), "view_public": id(0x44), "authorization": "abcd" }).to_string())),
                "/aps/leg" => Ok((200, r#"{"prepared":"cafe"}"#.to_owned())),
                "/aps/submit" => Ok((200, r#"{"outcome":"finalized"}"#.to_owned())),
                _ => Ok((404, r#"{"error":"not found"}"#.to_owned())),
            })
        }
    }

    impl Peer for FakePeer {
        fn call(&self, target: &str, method: &str, path: &str, body: &str) -> Result<(u16, String)> {
            self.calls.lock().unwrap().push((target.to_owned(), method.to_owned(), path.to_owned(), body.to_owned()));
            (self.answer)(target, path, body)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};

    use super::{testkit::*, *};

    const BI: &str = "https://gateway.rd-iroha3-bi.svc.cluster.local:8443";
    const BANK_A: &str = "https://gateway.rd-iroha3-bank-a.svc.cluster.local:8443";
    const BANK_B: &str = "https://gateway.rd-iroha3-bank-b.svc.cluster.local:8443";

    /// The BI driver's account is `account(7)`, bank A's `account(8)`, bank B's `account(9)`.
    fn driver(me: u8) -> FakeBackend {
        FakeBackend { me: account(me), ..FakeBackend::default() }
    }

    fn coordinator() -> ApsConfig {
        ApsConfig { coordinator: true, peers: BTreeMap::from([(account(8), BANK_A.to_owned()), (account(9), BANK_B.to_owned())]), ..ApsConfig::default() }
    }

    fn bank() -> ApsConfig {
        ApsConfig { coordinator_url: Some(BI.to_owned()), ..ApsConfig::default() }
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    fn calls(backend: &FakeBackend) -> Vec<&'static str> {
        backend.calls.lock().unwrap().clone()
    }

    fn intent_body(intent: &str, asset: &str, to: &str, amount: &str) -> String {
        serde_json::json!({ "intent": intent, "asset": asset, "to": to, "amount": amount }).to_string()
    }

    fn leg_body(intent: &str, ordinal: u8, to: &str, amount: &str) -> String {
        let out = serde_json::json!({ "authority": id(0x11), "view_public": id(0x22), "authorization": "abcd" });
        let sponsor = serde_json::json!({ "authority": id(0x55), "view_public": id(0x66), "authorization": "abcd", "active": ordinal == 0 });
        serde_json::json!({
            "intent": intent, "ordinal": ordinal, "manifest": "abcd", "authority_digest": id(0xdd), "salt": id(0xcc),
            "recipient": to, "amount": amount, "recipient_output": out, "sponsor_output": sponsor,
        })
        .to_string()
    }

    fn address_body() -> String {
        serde_json::json!({ "bundle_id": id(0xbb), "pool_id": id(1), "leg_ordinal": 0, "route": "0a", "expiry_height": 10, "network_id": "ee" }).to_string()
    }

    fn pay_body(intent: &str, asset: &str, from: &str, to: &str, amount: &str) -> String {
        serde_json::json!({ "kind": "pay", "intent": intent, "asset": asset, "from": from, "to": to, "amount": amount }).to_string()
    }

    fn dvp_body(buyer: &str, seller: &str, rd: &str, dfabi: &str) -> String {
        serde_json::json!({ "kind": "dvp", "intent_rd": id(1), "intent_dfabi": id(2), "buyer": buyer, "seller": seller, "rd": rd, "dfabi": dfabi }).to_string()
    }

    #[test]
    fn an_intent_is_one_shot() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let (status, response) = aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "intent": intent })));
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "prepared": "beef" })));
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403, "the intent is spent");
        assert_eq!(calls(&backend), ["prove"]);
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 409, "a spent intent is not registered again");
    }

    #[test]
    fn the_same_intent_with_other_terms_is_409_and_keeps_the_stored_terms() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200, "same terms again is harmless");
        for other in [intent_body(&intent, "rd", &to, "6"), intent_body(&intent, "dfabi", &to, "5"), intent_body(&intent, "rd", &account(7), "5")] {
            let (status, response) = aps.route("POST", "/aps/intent", &other);
            assert_eq!(status, 409, "{other}");
            assert!(json(&response)["error"].is_string());
        }
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "6")).0, 403, "the rejected terms were not stored");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 200, "the first terms still hold");
    }

    #[test]
    fn an_intent_expires_after_fifteen_minutes() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let start = std::time::Instant::now();
        assert_eq!(aps.route_at(start, "POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let late = start + Duration::from_secs(15 * 60 + 1);
        assert_eq!(aps.route_at(late, "POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403);
        assert!(calls(&backend).is_empty());
        let early = start + Duration::from_secs(14 * 60);
        assert_eq!(aps.route_at(early, "POST", "/aps/intent", &intent_body(&id(2), "rd", &to, "5")).0, 200);
        assert_eq!(aps.route_at(early, "POST", "/aps/leg", &leg_body(&id(2), 0, &to, "5")).0, 200);
    }

    #[test]
    fn a_leg_without_a_matching_intent_is_403_and_never_proves() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!(status, 403);
        assert!(json(&response)["error"].is_string());
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        // another recipient, another amount, the other pool (ordinal 1 = dfabi): none of them is what was approved
        for bad in [leg_body(&intent, 0, &account(7), "5"), leg_body(&intent, 0, &to, "6"), leg_body(&intent, 1, &to, "5")] {
            assert_eq!(aps.route("POST", "/aps/leg", &bad).0, 403, "{bad}");
        }
        assert!(calls(&backend).is_empty(), "no proving without a matching intent");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 200, "a refused leg did not spend the intent");
        assert_eq!(calls(&backend), ["prove"]);
    }

    #[test]
    fn an_intent_is_spent_even_when_proving_fails() {
        let backend = FakeBackend { error: Some("read /keys/bank-a.note: denied".to_owned()), ..driver(8) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!(status, 502);
        assert!(!response.contains(".note") && !response.contains(".seed"), "{response}");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403, "a retry needs a new intent");
        assert_eq!(calls(&backend), ["prove"]);
    }

    #[test]
    fn address_signs_for_the_own_account_and_needs_no_intent() {
        let (backend, peer) = (driver(9), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("POST", "/aps/address", &address_body());
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "authority": id(0x11), "view_public": id(0x22), "authorization": "abcd" })));
        assert_eq!(calls(&backend), ["address"]);
    }

    #[test]
    fn wallet_is_a_get_and_returns_what_the_backend_read() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("GET", "/aps/wallet", "");
        assert_eq!((status, json(&response)["balances"]["rd"].as_str()), (200, Some("5")));
        assert_eq!(aps.route("POST", "/aps/wallet", "{}").0, 405);
        assert_eq!(calls(&backend), ["wallet"]);
    }

    #[test]
    fn a_bank_driver_forwards_submit_verbatim_to_the_coordinator_url_and_returns_its_answer() {
        let backend = driver(8);
        let peer = FakePeer::with(|_, _, _| Ok((403, r#"{"error":"payer refused"}"#.to_owned())));
        let aps = Aps::new(&backend, &peer, bank());
        let body = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let (status, response) = aps.route("POST", "/aps/submit", &body);
        assert_eq!((status, json(&response)), (403, serde_json::json!({ "error": "payer refused" })));
        assert_eq!(*peer.calls.lock().unwrap(), vec![(BI.to_owned(), "POST".to_owned(), "/aps/submit".to_owned(), body)]);
        assert!(calls(&backend).is_empty(), "a bank does no coordinating");
    }

    #[test]
    fn a_dvp_submit_is_forwarded_too_and_a_bank_without_coordinator_url_answers_503() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let forwarding = Aps::new(&backend, &peer, bank());
        let body = dvp_body(&account(9), &account(8), "5", "7");
        assert_eq!(forwarding.route("POST", "/aps/submit", &body), (200, r#"{"outcome":"finalized"}"#.to_owned()));
        assert_eq!(peer.calls.lock().unwrap()[0].3, body);
        let lone_peer = FakePeer::standard();
        let alone = Aps::new(&backend, &lone_peer, ApsConfig::default());
        let (status, response) = alone.route("POST", "/aps/submit", &body);
        assert_eq!(status, 503);
        assert!(json(&response)["error"].is_string());
        assert!(lone_peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_peer_that_cannot_be_reached_is_502() {
        let (backend, peer) = (driver(8), FakePeer::with(|_, _, _| Err(eyre::eyre!("connection refused"))));
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!((status, json(&response)), (502, serde_json::json!({ "error": "connection refused" })));
    }

    #[test]
    fn the_coordinator_collects_the_address_and_the_leg_from_their_owners_then_settles() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let body = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let (status, response) = aps.route("POST", "/aps/submit", &body);
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "outcome": "finalized", "bundle_id": id(0xbb), "carrier_tx": "txh", "height": 42 })));
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        assert_eq!(route, [(BANK_B, "/aps/address"), (BANK_A, "/aps/leg")], "address from the recipient, leg from the payer");
        let leg = json(&sent[1].3);
        assert_eq!(
            (leg["intent"].as_str(), leg["ordinal"].as_u64(), leg["recipient"].as_str(), leg["amount"].as_str(), leg["manifest"].as_str()),
            (Some(id(1).as_str()), Some(0), Some(account(9).as_str()), Some("5"), Some("abcd"))
        );
        assert_eq!(leg["recipient_output"]["authority"], id(0x33), "the recipient's own answer");
        assert_eq!(leg["sponsor_output"]["active"], true, "leg 0 pays the sponsor");
        // BI's own side: manifest, its sponsor output per leg, the BI -> BI companion leg without HTTP, then settle
        assert_eq!(calls(&backend), ["begin_bundle", "sponsor_output", "address", "sponsor_output", "prove", "settle"]);
    }

    #[test]
    fn a_dvp_asks_the_buyer_for_the_rd_leg_and_the_seller_for_the_dfabi_leg() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, _) = aps.route("POST", "/aps/submit", &dvp_body(&account(8), &account(9), "5", "7"));
        assert_eq!(status, 200);
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        assert_eq!(route, [(BANK_B, "/aps/address"), (BANK_A, "/aps/leg"), (BANK_A, "/aps/address"), (BANK_B, "/aps/leg")]);
        let (rd, dfabi) = (json(&sent[1].3), json(&sent[3].3));
        assert_eq!((rd["intent"].as_str(), rd["amount"].as_str(), rd["recipient"].as_str()), (Some(id(1).as_str()), Some("5"), Some(account(9).as_str())));
        assert_eq!((dfabi["intent"].as_str(), dfabi["amount"].as_str(), dfabi["recipient"].as_str()), (Some(id(2).as_str()), Some("7"), Some(account(8).as_str())));
        assert_eq!((dfabi["ordinal"].as_u64(), dfabi["sponsor_output"]["active"].as_bool()), (Some(1), Some(false)));
    }

    #[test]
    fn a_payer_that_refuses_its_leg_stops_the_submit_before_settle() {
        let backend = driver(7);
        let peer = FakePeer::with(|_, path, _| match path {
            "/aps/leg" => Ok((403, r#"{"error":"no matching intent"}"#.to_owned())),
            _ => Ok((200, serde_json::json!({ "authority": id(0x33), "view_public": id(0x44), "authorization": "abcd" }).to_string())),
        });
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!(status, 403);
        assert!(json(&response)["error"].as_str().unwrap().contains("no matching intent"), "{response}");
        assert!(!calls(&backend).contains(&"settle"));
    }

    #[test]
    fn a_leg_paid_by_the_coordinator_still_needs_its_own_intent_but_the_companion_does_not() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let body = pay_body(&id(1), "rd", &account(7), &account(9), "5");
        assert_eq!(aps.route("POST", "/aps/submit", &body).0, 403, "BI's issuance leg without a registered intent");
        assert!(!calls(&backend).contains(&"prove") && !calls(&backend).contains(&"settle"));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(1), "rd", &account(9), "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/submit", &body).0, 200);
        assert_eq!(calls(&backend).iter().filter(|call| **call == "prove").count(), 2, "the issuance leg and the companion");
    }

    #[test]
    fn a_party_without_a_configured_gateway_is_400_before_anything_is_prepared() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, ApsConfig { coordinator: true, ..ApsConfig::default() });
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!(status, 400);
        assert!(json(&response)["error"].is_string());
        assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_aborted_bundle_is_a_200_with_outcome_aborted() {
        let backend = FakeBackend { aborts: true, ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "outcome": "aborted", "bundle_id": id(0xbb), "carrier_tx": null, "height": null })));
    }

    #[test]
    fn two_concurrent_submits_on_the_coordinator_run_one_after_the_other() {
        let backend = FakeBackend { settle_delay: Duration::from_millis(150), ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let to = account(9);
        let bodies: Vec<String> = [1u8, 2]
            .iter()
            .map(|n| {
                assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(*n), "rd", &to, "5")).0, 200);
                pay_body(&id(*n), "rd", &account(7), &to, "5")
            })
            .collect();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| aps.route("POST", "/aps/submit", &bodies[0]));
            let second = scope.spawn(|| aps.route("POST", "/aps/submit", &bodies[1]));
            assert_eq!(first.join().unwrap().0, 200);
            assert_eq!(second.join().unwrap().0, 200);
        });
        assert_eq!(backend.max_active.load(Ordering::SeqCst), 1, "two bundles were in settle at once");
        assert_eq!(calls(&backend).iter().filter(|call| **call == "settle").count(), 2);
    }

    #[test]
    fn a_driver_keeps_answering_address_and_leg_while_its_own_submit_waits_on_the_coordinator() {
        // a bank forwards `/aps/submit` to BI while BI asks the same bank for `/aps/leg`
        let backend = driver(8);
        let peer = FakePeer::with(|_, _, _| {
            std::thread::sleep(Duration::from_millis(200));
            Ok((200, r#"{"outcome":"finalized"}"#.to_owned()))
        });
        let aps = Aps::new(&backend, &peer, bank());
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5")));
            std::thread::sleep(Duration::from_millis(50));
            let started = std::time::Instant::now();
            assert_eq!(aps.route("POST", "/aps/address", &address_body()).0, 200);
            assert!(started.elapsed() < Duration::from_millis(150), "address waited for the forwarded submit");
            assert_eq!(waiting.join().unwrap().0, 200);
        });
    }

    #[test]
    fn malformed_submit_bodies_are_400_and_touch_neither_backend_nor_peer() {
        let ok = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let dvp = dvp_body(&account(8), &account(9), "5", "7");
        let cases = [
            String::new(),
            "not json".to_owned(),
            "{}".to_owned(),
            r#"{"kind":"mint"}"#.to_owned(),
            r#"{"kind":"pay"}"#.to_owned(),
            r#"{"kind":"dvp"}"#.to_owned(),
            ok.replace('}', r#","extra":1}"#),
            pay_body("abcd", "rd", &account(8), &account(9), "5"),
            pay_body(&id(1), "gold", &account(8), &account(9), "5"),
            pay_body(&id(1), "rd", "not-a-key", &account(9), "5"),
            pay_body(&id(1), "rd", &account(8), "not-a-key", "5"),
            pay_body(&id(1), "rd", &account(8), &account(9), "0"),
            pay_body(&id(1), "rd", &account(8), &account(9), "-1"),
            pay_body(&id(1), "rd", &account(8), &account(8), "5"),
            dvp.replace('}', r#","extra":1}"#),
            dvp_body(&account(8), &account(9), "0", "7"),
            dvp_body(&account(8), &account(9), "5", "x"),
            dvp_body(&account(8), &account(8), "5", "7"),
            dvp.replace(&id(1), "abcd"),
        ];
        for config in [coordinator(), bank()] {
            let (backend, peer) = (driver(7), FakePeer::standard());
            let aps = Aps::new(&backend, &peer, config);
            for bad in &cases {
                let (status, response) = aps.route("POST", "/aps/submit", bad);
                assert_eq!(status, 400, "{bad:?}");
                assert!(json(&response)["error"].is_string());
            }
            assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_intent_address_and_leg_bodies_are_400_and_touch_nothing() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let to = account(9);
        let intent = intent_body(&id(1), "rd", &to, "5");
        let leg = leg_body(&id(1), 0, &to, "5");
        let address = address_body();
        let cases: Vec<(&str, String)> = vec![
            ("/aps/intent", String::new()),
            ("/aps/intent", "x".to_owned()),
            ("/aps/intent", "{}".to_owned()),
            ("/aps/intent", intent.replace('}', r#","extra":1}"#)),
            ("/aps/intent", intent_body("abcd", "rd", &to, "5")),
            ("/aps/intent", intent_body(&id(1), "gold", &to, "5")),
            ("/aps/intent", intent_body(&id(1), "rd", "not-a-key", "5")),
            ("/aps/intent", intent_body(&id(1), "rd", &to, "0")),
            ("/aps/intent", intent_body(&id(1), "rd", &to, "1.5")),
            ("/aps/leg", String::new()),
            ("/aps/leg", "{}".to_owned()),
            ("/aps/leg", leg.replace('}', r#","extra":1}"#)),
            ("/aps/leg", leg_body(&id(1), 2, &to, "5")),
            ("/aps/leg", leg_body("abcd", 0, &to, "5")),
            ("/aps/leg", leg_body(&id(1), 0, "not-a-key", "5")),
            ("/aps/leg", leg_body(&id(1), 0, &to, "0")),
            ("/aps/leg", leg.replace(r#""manifest":"abcd""#, r#""manifest":"xyz""#)),
            ("/aps/address", String::new()),
            ("/aps/address", "{}".to_owned()),
            ("/aps/address", address.replace('}', r#","extra":1}"#)),
            ("/aps/address", address.replace(&id(0xbb), "abcd")),
            ("/aps/address", address.replace(r#""leg_ordinal":0"#, r#""leg_ordinal":2"#)),
            ("/aps/address", address.replace(r#""route":"0a""#, r#""route":"zz""#)),
        ];
        for (path, bad) in &cases {
            let (status, response) = aps.route("POST", path, bad);
            assert_eq!(status, 400, "{path} {bad:?}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(calls(&backend).is_empty());
    }

    #[test]
    fn unknown_aps_routes_are_404_and_known_ones_with_the_wrong_method_are_405() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        for path in ["/aps", "/aps/", "/aps/keys", "/aps/submit/x", "/aps/wallet?x=1", "/aps/Intent"] {
            assert_eq!(aps.route("GET", path, "").0, 404, "GET {path}");
            assert_eq!(aps.route("POST", path, "{}").0, 404, "POST {path}");
        }
        for (method, path) in [("GET", "/aps/intent"), ("GET", "/aps/address"), ("GET", "/aps/leg"), ("GET", "/aps/submit"), ("POST", "/aps/wallet"), ("DELETE", "/aps/leg")] {
            assert_eq!(aps.route(method, path, "{}").0, 405, "{method} {path}");
        }
        assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn no_response_names_a_key_file_or_carries_secret_material() {
        let failing = FakeBackend { error: Some("read /keys/bank-a.seed: denied; /keys/bank-a.note; /keys/bi-auditor.hybrid; /etc/client.toml".to_owned()), ..driver(7) };
        let healthy = driver(7);
        let (peer, to) = (FakePeer::standard(), account(9));
        let mut all = Vec::new();
        for backend in [&failing, &healthy] {
            let aps = Aps::new(backend, &peer, coordinator());
            all.push(aps.route("POST", "/aps/intent", &intent_body(&id(1), "rd", &to, "5")).1);
            all.push(aps.route("POST", "/aps/leg", &leg_body(&id(1), 0, &to, "5")).1);
            all.push(aps.route("POST", "/aps/address", &address_body()).1);
            all.push(aps.route("GET", "/aps/wallet", "").1);
            all.push(aps.route("POST", "/aps/submit", &pay_body(&id(2), "rd", &account(8), &to, "5")).1);
            all.push(aps.route("POST", "/aps/submit", "garbage").1);
            all.push(aps.route("GET", "/aps/nope", "").1);
        }
        assert!(all.iter().any(|response| response.contains("error")));
        for response in all {
            for secret in [".seed", ".note", ".hybrid", "client.toml"] {
                assert!(!response.contains(secret), "{secret} in {response}");
            }
        }
    }
}
