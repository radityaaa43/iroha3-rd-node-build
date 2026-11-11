//! rd-dfabi: private RD/DFABI settlement driver for the Iroha 3 PoC (plan 2, item (b)).
//!
//!   rd-dfabi keys new <dir> <name>     write <dir>/<name>.seed (0600), print its public key
//!   rd-dfabi keys new-hybrid <dir> <name>  write <dir>/<name>.hybrid (0600): auditor capsule key
//!   rd-dfabi keys show <dir> <name>    print the public key of an existing seed
//!   rd-dfabi auditor <config>          run the BI auditor service
//!   rd-dfabi prove-selftest <peers.json>  offline: prove one leg, print time and peak RSS
//!   rd-dfabi prove-continuation-selftest <peers.json>  offline gate G1a: spend a received note
//!   rd-dfabi keys new-note <dir> <name>  write <dir>/<name>.note (0600): note spend + view secrets
//!   rd-dfabi pool-init <config> --rd-reserve N --dfabi-reserve N  one-time: long-lived RD/DFABI pools, BI reserve
//!   rd-dfabi pay <config> --asset rd|dfabi --from P --to Q --amount N  private payment in the shared pools
//!   rd-dfabi dvp-shared <config> --buyer P --seller P --rd N --dfabi N   DvP in the shared pools
//!   rd-dfabi wallet <config> --party P   balances and movements from the chain (wallet_json=)
//!   rd-dfabi settle-grant <config> --to <public-key> --give <asset>:<n> --take <asset>:<n> --intent <64-hex>
//!            D-native DvP (iroha3 S17): grant CanExecuteSettlement from the config's OWN account (its client.toml key)
//!            to <public-key>, bound to the exact DvP (own --give leaves me, --take arrives at me)
//!   rd-dfabi dvp-native <config> --counterparty <public-key> --give <asset>:<n> --take <asset>:<n> --intent <64-hex>
//!            submit the DvpIsi (two legs, AllOrNothing, settlement id dvp_<intent>) from the config's OWN account;
//!            prints tx_hash and status. The counterparty must have run settle-grant with the mirrored terms first.
//!   rd-dfabi keys client-toml <dir> <name> --torii <url> --chain <id> --network-id-file <path> [--domain D]
//!            derive <dir>/client.toml (0600, never overwritten) from <dir>/<name>.seed; the key is never printed
//!   rd-dfabi server <config> --listen <addr>   per-bank HTTP mode (docs/server-mode.md): GET /healthz, POST /settle-grant, POST /dvp-native
//!   rd-dfabi abort-bundle <config> --bundle <hex>  release the pool reservations of a stuck bundle
//!   rd-dfabi pool-history <config> --asset rd|dfabi  rebuilt pool head (gate G3)
//!   rd-dfabi dvp <config> --buyer P --seller P --rd N --dfabi N
//!            [--rd-funding N] [--dfabi-funding N] [--expect finalized|aborted] [--replay]
//!
//! A DvP is one bundle: leg 0 RD buyer -> seller in ds-rd, leg 1 DFABI seller -> buyer in
//! ds-dfabi. Each payer's origin note (funding) is issued when its leg's pool is activated.

mod aps;
mod auditor;
mod client_toml;
mod config;
mod dvp_native;
mod history;
mod mint_finality;
mod server;
mod http;
mod pools;
mod tree;
mod wallet;

use std::{collections::BTreeMap, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use eyre::{Result, bail, eyre};

use crate::{
    aps::{Expect, Leg, Options},
    config::{Config, read_seed, signing_key},
};

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    match args.as_slice() {
        ["keys", "new", dir, name] => {
            let path = Path::new(dir).join(format!("{name}.seed"));
            let seed: [u8; 32] = rand::random();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .write_all(hex::encode(seed).as_bytes())?;
            println!("{name} {}", signing_key(&seed).public_key());
            Ok(())
        }
        ["keys", "new-hybrid", dir, name] => {
            let path = Path::new(dir).join(format!("{name}.hybrid"));
            auditor::write_hybrid(&path)?;
            println!("{name} hybrid key written to {}", path.display());
            Ok(())
        }
        ["keys", "new-note", dir, name] => {
            let path = Path::new(dir).join(format!("{name}.note"));
            let keys = wallet::NoteKeys::random();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .write_all(format!("{}{}", hex::encode(keys.spend), hex::encode(keys.view)).as_bytes())?;
            println!("{name} note keys written to {}", path.display());
            Ok(())
        }
        ["keys", "mint-finality", dir, name, peer] => {
            println!("{}", mint_finality::mint_finality(Path::new(dir), name, peer, 0)?);
            Ok(())
        }
        ["keys", "mint-finality", dir, name, peer, epoch] => {
            println!("{}", mint_finality::mint_finality(Path::new(dir), name, peer, epoch.parse()?)?);
            Ok(())
        }
        ["keys", "mint-finality-roster", out, triples @ ..] => {
            let triples = triples.iter().map(Path::new).collect::<Vec<_>>();
            mint_finality::roster(Path::new(out), &triples)
        }
        ["keys", "client-toml", dir, name, rest @ ..] => {
            let flags = flags(rest)?;
            let domain = flags.0.get("domain").copied().unwrap_or("wonderland.universal");
            let path = client_toml::write(Path::new(dir), name, flags.get("torii")?, flags.get("chain")?, flags.get("network-id-file")?, domain)?;
            println!("{name} client.toml written to {}", path.display());
            Ok(())
        }
        ["keys", "show", dir, name] => {
            let seed = read_seed(&Path::new(dir).join(format!("{name}.seed")))?;
            println!("{name} {}", signing_key(&seed).public_key());
            Ok(())
        }
        ["auditor", config] => auditor::run(Config::load(Path::new(config))?),
        ["prove-selftest", peers_json] => aps::prove_selftest(Path::new(peers_json)),
        ["prove-continuation-selftest", peers_json] => aps::prove_continuation_selftest(Path::new(peers_json)),
        ["dvp", config, rest @ ..] => dvp(&Config::load(Path::new(config))?, rest),
        ["pool-init", config, rest @ ..] => {
            let flags = flags(rest)?;
            pools::pool_init(&Config::load(Path::new(config))?, flags.number("rd-reserve")?, flags.number("dfabi-reserve")?)
        }
        ["pool-history", config, "--asset", asset] => pools::pool_history(&Config::load(Path::new(config))?, pools::Asset::parse(asset)?),
        ["pay", config, rest @ ..] => {
            let flags = flags(rest)?;
            pools::pay(
                &Config::load(Path::new(config))?,
                pools::Asset::parse(flags.get("asset")?)?,
                flags.get("from")?,
                flags.get("to")?,
                flags.number("amount")?,
                &Options { expect: Expect::Finalized, replay: false },
            )
        }
        ["dvp-shared", config, rest @ ..] => {
            let flags = flags(rest)?;
            pools::dvp(
                &Config::load(Path::new(config))?,
                flags.get("buyer")?,
                flags.get("seller")?,
                flags.number("rd")?,
                flags.number("dfabi")?,
                &Options { expect: Expect::Finalized, replay: false },
            )
        }
        ["settle-grant", config, rest @ ..] => {
            let flags = flags(rest)?;
            let hash = dvp_native::settle_grant(&Config::load(Path::new(config))?, flags.get("to")?, flags.get("give")?, flags.get("take")?, flags.get("intent")?)?;
            println!("tx_hash={hash} status=Applied");
            Ok(())
        }
        ["dvp-native", config, rest @ ..] => {
            let flags = flags(rest)?;
            let hash = dvp_native::dvp_native(&Config::load(Path::new(config))?, flags.get("counterparty")?, flags.get("give")?, flags.get("take")?, flags.get("intent")?)?;
            println!("tx_hash={hash} status=Applied");
            Ok(())
        }
        ["server", config, "--listen", addr] => server::run(Config::load(Path::new(config))?, addr),
        ["abort-bundle", config, "--bundle", bundle] => pools::abort_bundle(&Config::load(Path::new(config))?, bundle),
        ["wallet", config, "--party", party] => pools::wallet(&Config::load(Path::new(config))?, party),
        _ => bail!("usage: see the header of apps/rd-dfabi/src/main.rs"),
    }
}

fn dvp(cfg: &Config, rest: &[&str]) -> Result<()> {
    let mut flags = BTreeMap::new();
    let mut replay = false;
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        if *flag == "--replay" {
            replay = true;
            continue;
        }
        let value = iter.next().ok_or_else(|| eyre!("{flag} needs a value"))?;
        flags.insert(flag.trim_start_matches("--"), *value);
    }
    let get = |name: &str| flags.get(name).copied().ok_or_else(|| eyre!("missing --{name}"));
    let number = |name: &str, default: Option<u128>| -> Result<u128> {
        match flags.get(name) {
            Some(value) => Ok(value.parse()?),
            None => default.ok_or_else(|| eyre!("missing --{name}")),
        }
    };
    let wallet = |party: &str| Ok::<_, eyre::Report>(signing_key(&cfg.seed(party)?));
    let (buyer, seller) = (get("buyer")?, get("seller")?);
    let expect = match flags.get("expect").copied().unwrap_or("finalized") {
        "finalized" => Expect::Finalized,
        "aborted" => Expect::Aborted,
        other => bail!("--expect {other}"),
    };
    let legs = vec![
        Leg {
            lane: cfg.lanes.rd,
            asset: cfg.assets.rd.parse()?,
            payer: wallet(buyer)?,
            recipient: wallet(seller)?,
            funding: number("rd-funding", Some(1_000))?,
            amount: number("rd", None)?,
        },
        Leg {
            lane: cfg.lanes.dfabi,
            asset: cfg.assets.dfabi.parse()?,
            payer: wallet(seller)?,
            recipient: wallet(buyer)?,
            funding: number("dfabi-funding", Some(100))?,
            amount: number("dfabi", None)?,
        },
    ];
    aps::run_dvp(cfg, legs, &Options { expect, replay })
}

struct Flags<'a>(BTreeMap<&'a str, &'a str>);

impl<'a> Flags<'a> {
    fn get(&self, name: &str) -> Result<&'a str> {
        self.0.get(name).copied().ok_or_else(|| eyre!("missing --{name}"))
    }

    fn number(&self, name: &str) -> Result<u128> {
        Ok(self.get(name)?.parse()?)
    }
}

fn flags<'a>(rest: &[&'a str]) -> Result<Flags<'a>> {
    let mut map = BTreeMap::new();
    let mut iter = rest.iter();
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| eyre!("{flag} needs a value"))?;
        map.insert(flag.trim_start_matches("--"), *value);
    }
    Ok(Flags(map))
}
