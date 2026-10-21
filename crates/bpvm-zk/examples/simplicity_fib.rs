//! The Simplicity verifier of a guest program's proof (feature `simplicity`): prove over
//! secp256k1 for a transaction, compile the verifier, run it as a Liquid node would.
//!
//! cargo run --release -p bpvm-zk --example simplicity_fib --features simplicity [guest.elf]

use bpvm_emu::{Image, Machine};
use bulletproofs::curve::Secp256k1;
use bulletproofs::simplicity::{dummy_env, sighash_of};
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib/fib.elf").to_string());
    let img = Image::from_elf(&std::fs::read(&path).expect("guest ELF")).unwrap();
    let trace = Machine::from_image(&img).run(1 << 20).expect("runs");
    let (st, wit) = bpvm_zk::witness_for::<Secp256k1>(&img, &trace).unwrap();
    let env = dummy_env();
    let t0 = Instant::now();
    let (proof, stats) = bpvm_zk::vm::simplicity::prove(&st, &wit, &sighash_of(&env)).unwrap();
    println!("{}: {} steps, {} BP++ gates, {} linear slots, proof {} B ({:.1?})", path, st.steps, stats.gates, stats.linear, stats.proof_bytes, t0.elapsed());
    let t1 = Instant::now();
    let sv = bpvm_zk::vm::simplicity::compile(&st).unwrap();
    println!("compiled in {:.1?}: {:?}", t1.elapsed(), sv.stats());
    let t2 = Instant::now();
    match sv.execute(&sv.witness(&proof).unwrap(), &env) {
        Ok(r) => println!("ran in {:.1?}: cost {} mWU, budget {} mWU, program {} B, witness {} B, cells {}", t2.elapsed(), r.cost_mwu, r.budget_mwu, r.program_bytes, r.witness_bytes, r.cells),
        Err(e) => println!("ran in {:.1?}: {:?}", t2.elapsed(), e),
    }
}
