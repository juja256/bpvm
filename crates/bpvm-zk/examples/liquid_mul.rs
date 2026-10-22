//! Deploy the Simplicity verifier of the `mul` guest (c = a · b, a and b private) on Liquid
//! testnet, and spend it with a proof (feature `simplicity`).
//!
//! ```text
//! cargo run --release -p bpvm-zk --features simplicity --example liquid_mul -- address [--state FILE] [a=N b=N]
//! cargo run --release -p bpvm-zk --features simplicity --example liquid_mul -- spend TXID:VOUT [--to ADDRESS] [--fee-rate SAT_PER_VB] [--state FILE] [--broadcast]
//! ```
//!
//! `address` draws the blindings of the commitments to `a` and `b`, writes them with the
//! values to the state file (default `liquid_mul.state`; keep it: the verifier is bound to
//! these commitments) and prints the contract's unconfidential address. Send explicit L-BTC to
//! it (the testnet faucet: https://liquidtestnet.com/faucet).
//!
//! `spend` fetches the funding transaction from Esplora (blockstream.info/liquidtestnet),
//! builds the spending transaction (to `--to`, by default back to the contract, minus the fee
//! at `--fee-rate`, default 0.1 sat/vB), proves the statement for it, runs the verifier as a
//! node would and writes the transaction to `liquid_mul.tx.hex`. With `--broadcast` it also
//! posts the transaction to Esplora.

use std::process::Command;
use std::str::FromStr;

use bpvm_emu::{Image, IoKind, Machine};
use bpvm_zk::liquid::{self, Contract};
use bulletproofs::curve::ff::Field as _;
use bulletproofs::curve::{Curve, Field, Secp256k1};
use bulletproofs::simplicity::lang::elements::{encode, Address, AddressParams, BlockHash, OutPoint, Transaction, Txid};
use bulletproofs::simplicity::sighash_of;

type K = <Secp256k1 as Curve>::Scalar;

const ESPLORA: &str = "https://blockstream.info/liquidtestnet/api";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let state_path = flag("--state").unwrap_or_else(|| "liquid_mul.state".into());
    match args.first().map(String::as_str) {
        Some("address") => {
            let value = |n: &str| args.iter().find_map(|a| a.strip_prefix(&format!("{n}="))).map(|v| v.parse::<u64>().map_err(|e| e.to_string())).transpose();
            let (a, b) = (value("a")?.unwrap_or(100_003), value("b")?.unwrap_or(70_001));
            let mut rng = rand::thread_rng();
            let blindings = [K::random(&mut rng), K::random(&mut rng)];
            let state = State { a, b, blindings };
            let (st, _) = statement(&state)?;
            let sv = bpvm_zk::vm::simplicity::compile(&st).map_err(|e| format!("{e:?}"))?;
            let contract = Contract::new(sv.cmr());
            if std::path::Path::new(&state_path).exists() {
                return Err(format!("{state_path} exists; remove it or pass --state"));
            }
            std::fs::write(&state_path, state.encode(&sv.cmr().to_string())).map_err(|e| e.to_string())?;
            println!("state:    {state_path} (values and blindings: private)");
            println!("CMR:      {}", sv.cmr());
            println!("cost:     {} mWU, budget {} mWU ({})", sv.stats().cost_mwu, sv.stats().budget_mwu, sv.stats().lowering);
            println!("address:  {}", contract.address(&AddressParams::LIQUID_TESTNET));
            println!("c = {} (public), a, b committed", a as u128 * b as u128);
            Ok(())
        }
        Some("spend") => {
            let outpoint = args.get(1).ok_or("spend TXID:VOUT")?;
            let (txid, vout) = outpoint.split_once(':').ok_or("TXID:VOUT")?;
            let prevout = OutPoint::new(Txid::from_str(txid).map_err(|e| e.to_string())?, vout.parse().map_err(|_| "VOUT")?);
            let fee_rate: f64 = flag("--fee-rate").map(|r| r.parse().map_err(|_| "--fee-rate")).transpose()?.unwrap_or(0.1);
            let (state, cmr) = State::decode(&std::fs::read_to_string(&state_path).map_err(|e| format!("{state_path}: {e}"))?)?;
            let (st, wit) = statement(&state)?;
            let sv = bpvm_zk::vm::simplicity::compile(&st).map_err(|e| format!("{e:?}"))?;
            if sv.cmr().to_string() != cmr {
                return Err(format!("the verifier compiles to CMR {} but the state was made for {cmr} (another compiler?)", sv.cmr()));
            }
            let contract = Contract::new(sv.cmr());
            let genesis = BlockHash::from_str(get(&format!("{ESPLORA}/block-height/0"))?.trim()).map_err(|e| e.to_string())?;
            let funding: Transaction = encode::deserialize(&unhex(get(&format!("{ESPLORA}/tx/{txid}/hex"))?.trim())?).map_err(|e| e.to_string())?;
            let utxo = funding.output.get(prevout.vout as usize).ok_or("no such output")?.clone();
            if utxo.script_pubkey != contract.script_pubkey() {
                return Err("that output does not pay the contract".into());
            }
            let to = match flag("--to") {
                Some(a) => Address::from_str(&a).map_err(|e| e.to_string())?.script_pubkey(),
                None => contract.script_pubkey(),
            };
            // the fee depends on the weight, the weight (slightly) on the proof: build with a
            // first estimate, then again with the fee of the measured weight plus a margin
            let mut fee = liquid::fee_for(liquid::MAX_STANDARD_WEIGHT, fee_rate);
            for _ in 0..2 {
                let mut tx = liquid::spending_tx(prevout, &utxo, to.clone(), fee)?;
                let env = liquid::env(&tx, &utxo, &contract, genesis);
                let (proof, _) = bpvm_zk::vm::simplicity::prove(&st, &wit, &sighash_of(&env)).map_err(|e| format!("{e:?}"))?;
                let spend = sv.spend(&sv.witness(&proof).map_err(|e| format!("{e:?}"))?, &env).map_err(|e| format!("the verifier rejects: {e:?}"))?;
                liquid::set_witness(&mut tx, &contract, &spend);
                let weight = tx.weight();
                let needed = liquid::fee_for(weight + 400, fee_rate);
                if fee >= needed && fee <= needed + needed / 10 + 10 {
                    if weight > liquid::MAX_STANDARD_WEIGHT {
                        return Err(format!("weight {weight} over the standard limit"));
                    }
                    let hex = encode::serialize_hex(&tx);
                    std::fs::write("liquid_mul.tx.hex", &hex).map_err(|e| e.to_string())?;
                    println!("spend:    {} (weight {weight} WU, fee {fee} sat, cost {} of budget {} mWU)", tx.txid(), spend.report.cost_mwu, spend.report.budget_mwu);
                    println!("written:  liquid_mul.tx.hex");
                    if args.iter().any(|a| a == "--broadcast") {
                        println!("broadcast: {}", post(&format!("{ESPLORA}/tx"), &hex)?);
                    }
                    return Ok(());
                }
                fee = needed;
            }
            Err("the fee did not settle".into())
        }
        _ => Err("usage: liquid_mul address [--state FILE] [a=N b=N] | spend TXID:VOUT [--to ADDRESS] [--fee-rate R] [--state FILE] [--broadcast]".into()),
    }
}

/// The values and the blindings of the commitments to `a` and `b`.
struct State {
    a: u64,
    b: u64,
    blindings: [K; 2],
}

impl State {
    fn encode(&self, cmr: &str) -> String {
        format!("a={}\nb={}\nblinding_a={}\nblinding_b={}\ncmr={cmr}\n", self.a, self.b, hex(&self.blindings[0].to_bytes32()), hex(&self.blindings[1].to_bytes32()))
    }

    fn decode(s: &str) -> Result<(State, String), String> {
        let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).ok_or(format!("the state has no {k}"));
        let scalar = |k: &str| -> Result<K, String> {
            let b: [u8; 32] = unhex(get(k)?)?.try_into().map_err(|_| format!("{k}: 32 bytes"))?;
            K::from_bytes32(&b).ok_or(format!("{k}: not a scalar"))
        };
        let num = |k: &str| get(k)?.parse::<u64>().map_err(|e| format!("{k}: {e}"));
        Ok((State { a: num("a")?, b: num("b")?, blindings: [scalar("blinding_a")?, scalar("blinding_b")?] }, get("cmr")?.to_string()))
    }
}

/// The `mul` guest's statement and witness for the state's values and blindings.
fn statement(state: &State) -> Result<(bpvm_zk::Statement<Secp256k1>, bpvm_zk::Witness<K>), String> {
    let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/mul/mul.elf")).map_err(|e| format!("guest/mul/mul.elf: {e}"))?;
    let mut img = Image::from_elf(&bytes)?;
    let mut io = bpvm_zk::IoSpec::<K> { private_in: vec![], private_out: vec![], public_out: vec![] };
    for var in img.io.clone() {
        let (v, blinding) = match var.name.as_str() {
            "a" => (vec![state.a], Some(state.blindings[0])),
            "b" => (vec![state.b], Some(state.blindings[1])),
            _ => (vec![], None),
        };
        for (addr, w) in var.to_words(&v) {
            img.data.insert(addr, w);
        }
        for i in 0..var.count {
            match var.kind {
                IoKind::PrivateInput => io.private_in.push((var.words(i), blinding.ok_or("an unexpected private input")?)),
                IoKind::PrivateOutput => return Err("mul has no private outputs".into()),
                IoKind::PublicOutput => io.public_out.extend(var.words(i)),
                IoKind::PublicInput => {}
            }
        }
    }
    let trace = Machine::from_image(&img).run(1 << 20).map_err(|e| format!("{e:?}"))?;
    bpvm_zk::witness_with_io::<Secp256k1>(&img, &trace, &io)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

fn get(url: &str) -> Result<String, String> {
    let out = Command::new("curl").args(["-sSf", url]).output().map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("GET {url}: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn post(url: &str, body: &str) -> Result<String, String> {
    let out = Command::new("curl").args(["-sS", "-X", "POST", "--data-binary", "@-", url]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().and_then(|mut c| {
        use std::io::Write;
        c.stdin.take().expect("stdin").write_all(body.as_bytes())?;
        c.wait_with_output()
    });
    let out = out.map_err(|e| format!("curl: {e}"))?;
    Ok(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}
