//! Prover/verifier time of dalek R1CS vs number of multipliers (release build):
//! `cargo run --release -p bpvm-zk --example r1cs_scaling`
use std::time::Instant;

use bulletproofs::r1cs::{ConstraintSystem, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// A chain x_{i+1} = x_i * x_i + i, i.e. one multiplier per step.
fn chain<CS: ConstraintSystem>(cs: &mut CS, n: usize, x0: Option<Scalar>) {
    let mut x = x0;
    let (_, _, mut prev) = cs.allocate_multiplier(x.map(|v| (v, v))).unwrap();
    x = x.map(|v| v * v);
    for i in 1..n {
        let (l, r, o) = cs.allocate_multiplier(x.map(|v| (v, v))).unwrap();
        cs.constrain(l - prev);
        cs.constrain(r - prev);
        prev = o;
        x = x.map(|v| v * v);
        let _ = i;
    }
}

fn main() {
    let pc = PedersenGens::default();
    for log_n in [10, 12, 14, 16, 18] {
        let n = 1usize << log_n;
        let t0 = Instant::now();
        let bp = BulletproofGens::new(n, 1);
        let gens = t0.elapsed();

        let mut t = Transcript::new(b"scaling");
        let mut prover = Prover::new(&pc, &mut t);
        chain(&mut prover, n, Some(Scalar::from(3u64)));
        let t0 = Instant::now();
        let proof = prover.prove(&bp).unwrap();
        let prove = t0.elapsed();

        let mut t = Transcript::new(b"scaling");
        let mut verifier = Verifier::new(&mut t);
        chain(&mut verifier, n, None);
        let t0 = Instant::now();
        verifier.verify(&proof, &pc, &bp).unwrap();
        let verify = t0.elapsed();

        println!(
            "n = 2^{log_n:<2}  gens {gens:>9.2?}  prove {prove:>9.2?}  verify {verify:>9.2?}  proof {} B",
            proof.to_bytes().len()
        );
    }
}
