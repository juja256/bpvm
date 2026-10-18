//! How much do linear constraints cost in Bulletproofs R1CS? Fixed n multipliers plus L extra
//! linear constraints with T terms each; proof size and time vs L.
//! `cargo run --release -p bpvm-zk --example linear_cost`

use std::time::Instant;

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

const N: usize = 1 << 12;
const T: usize = 8;

/// N multipliers x_i * x_i = y_i, then L constraints sum_{t<T} x_{(j+t) mod N} = known.
fn circuit<CS: ConstraintSystem>(cs: &mut CS, l: usize, xs: Option<&[u64]>) {
    let mut vars: Vec<Variable> = Vec::with_capacity(N);
    for i in 0..N {
        let x = xs.map(|xs| Scalar::from(xs[i]));
        let (a, b, o) = cs.allocate_multiplier(x.map(|x| (x, x))).unwrap();
        cs.constrain(a - b);
        let _ = o;
        vars.push(a);
    }
    let value = |i: usize| (i as u64 * 7 + 3) % 1000;
    for j in 0..l {
        let mut lc = LinearCombination::default();
        let mut sum = 0u64;
        for t in 0..T {
            let i = (j * 31 + t) % N;
            lc = lc + vars[i];
            sum += value(i);
        }
        cs.constrain(lc - Scalar::from(sum));
    }
}

fn main() {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(N, 1);
    let xs: Vec<u64> = (0..N).map(|i| (i as u64 * 7 + 3) % 1000).collect();
    println!("n = {N} multipliers, linear constraints with {T} terms each\n");
    println!("| extra linear constraints | terms | prove | verify | proof |\n|---|---|---|---|---|");
    for l in [0usize, 1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20] {
        let t0 = Instant::now();
        let mut tr = Transcript::new(b"lin");
        let mut p = Prover::new(&pc, &mut tr);
        circuit(&mut p, l, Some(&xs));
        let proof: R1CSProof = p.prove(&bp).unwrap();
        let prove = t0.elapsed();

        let t1 = Instant::now();
        let mut tr = Transcript::new(b"lin");
        let mut v = Verifier::new(&mut tr);
        circuit(&mut v, l, None);
        v.verify(&proof, &pc, &bp).unwrap();
        let verify = t1.elapsed();
        println!("| {l} | {} | {prove:.2?} | {verify:.2?} | {} B |", l * T, proof.to_bytes().len());
    }
}
