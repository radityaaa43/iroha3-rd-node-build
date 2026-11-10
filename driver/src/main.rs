//! rd-dfabi: private RD/DFABI settlement driver for the Iroha 3 PoC (plan 2, item (b)).
//!
//!   rd-dfabi keys new <dir> <name>     write <dir>/<name>.seed (0600), print its public key
//!   rd-dfabi keys new-hybrid <dir> <name>  write <dir>/<name>.hybrid (0600): auditor capsule key
//!   rd-dfabi keys show <dir> <name>    print the public key of an existing seed
//!   rd-dfabi auditor <config>          run the BI auditor service
//!   rd-dfabi prove-selftest <peers.json>  offline: prove one leg, print time and peak RSS
//!   rd-dfabi prove-continuation-selftest <peers.json>  offline gate G1a: spend a received note
//!   rd-dfabi dvp <config> --buyer P --seller P --rd N --dfabi N
//!            [--rd-funding N] [--dfabi-funding N] [--expect finalized|aborted] [--replay]
//!
//! A DvP is one bundle: leg 0 RD buyer -> seller in ds-rd, leg 1 DFABI seller -> buyer in
//! ds-dfabi. Each payer's origin note (funding) is issued when its leg's pool is activated.

mod aps;
mod auditor;
mod config;
mod history;
mod http;
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
        ["keys", "show", dir, name] => {
            let seed = read_seed(&Path::new(dir).join(format!("{name}.seed")))?;
            println!("{name} {}", signing_key(&seed).public_key());
            Ok(())
        }
        ["auditor", config] => auditor::run(Config::load(Path::new(config))?),
        ["prove-selftest", peers_json] => aps::prove_selftest(Path::new(peers_json)),
        ["prove-continuation-selftest", peers_json] => aps::prove_continuation_selftest(Path::new(peers_json)),
        ["dvp", config, rest @ ..] => dvp(&Config::load(Path::new(config))?, rest),
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
