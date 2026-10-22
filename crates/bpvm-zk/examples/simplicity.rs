//! The Simplicity verifier of a guest program's proof (feature `simplicity`): prove over
//! secp256k1 for a transaction, compile the verifier, run it as a Liquid node would.
//!
//! cargo run --release -p bpvm-zk --example simplicity --features simplicity [guest.elf] [name=v1,v2 ...]
//!
//! Without arguments: `guest/fib/fib.elf`. Each `name=...` sets an input variable of the guest
//! (as `-i input.json` of the CLI does), e.g. `guest/mul/mul.elf a=100003 b=70001`; private
//! inputs and outputs are committed with blindings 2, 3, ...

use bpvm_emu::{Image, IoKind, Machine};
use bulletproofs::curve::{Curve, Secp256k1};
use bulletproofs::simplicity::{dummy_env, sighash_of};
use std::time::Instant;

type K = <Secp256k1 as Curve>::Scalar;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.iter().find(|a| !a.contains('=')).cloned().unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib/fib.elf").to_string());
    let values: Vec<(String, Vec<u64>)> = args
        .iter()
        .filter_map(|a| a.split_once('='))
        .map(|(n, v)| (n.to_string(), v.split(',').map(|x| x.trim().parse().expect("an integer value")).collect()))
        .collect();
    let mut img = Image::from_elf(&std::fs::read(&path).expect("guest ELF")).unwrap();
    let mut io = bpvm_zk::IoSpec::<K> { private_in: vec![], private_out: vec![], public_out: vec![] };
    let mut blind = 1u64;
    for var in img.io.clone() {
        if let Some((_, v)) = values.iter().find(|(n, _)| *n == var.name) {
            for (a, w) in var.to_words(v) {
                img.data.insert(a, w);
            }
        }
        for i in 0..var.count {
            blind += 1;
            match var.kind {
                IoKind::PrivateInput => io.private_in.push((var.words(i), K::from(blind))),
                IoKind::PrivateOutput => io.private_out.push((var.words(i), K::from(blind))),
                IoKind::PublicOutput => io.public_out.extend(var.words(i)),
                IoKind::PublicInput => {}
            }
        }
    }
    let trace = Machine::from_image(&img).run(1 << 20).expect("runs");
    let (st, wit) = bpvm_zk::witness_with_io::<Secp256k1>(&img, &trace, &io).unwrap();
    let env = dummy_env();
    let t0 = Instant::now();
    let (proof, stats) = bpvm_zk::vm::simplicity::prove(&st, &wit, &sighash_of(&env)).unwrap();
    println!("{}: {} steps, exit {}, {} BP++ gates, {} linear slots, proof {} B ({:.1?})", path, st.steps, st.exit_code, stats.gates, stats.linear, stats.proof_bytes, t0.elapsed());
    let t1 = Instant::now();
    let sv = bpvm_zk::vm::simplicity::compile(&st).unwrap();
    println!("compiled in {:.1?}: {:?}", t1.elapsed(), sv.stats());
    let t2 = Instant::now();
    match sv.execute(&sv.witness(&proof).unwrap(), &env) {
        Ok(r) => println!("ran in {:.1?}: cost {} mWU, budget {} mWU, program {} B, witness {} B, cells {}", t2.elapsed(), r.cost_mwu, r.budget_mwu, r.program_bytes, r.witness_bytes, r.cells),
        Err(e) => println!("ran in {:.1?}: {:?}", t2.elapsed(), e),
    }
}
