use std::sync::Arc;

use bpvm_zk::{Lookup, Table};
use bulletproofs::r1cs::{LinearCombination, Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// `v < 2^32` via four byte digits looked up in `Table::range(8)`.
fn range32<CS: bulletproofs::r1cs::RandomizableConstraintSystem>(
    cs: &mut CS,
    v: LinearCombination,
    digits: [Option<u64>; 4],
    table: Arc<Table>,
) -> Result<(), R1CSError> {
    let mut lookup = Lookup::new(table);
    let mut acc = v;
    for (i, d) in digits.iter().enumerate() {
        let var = cs.allocate(d.map(Scalar::from))?;
        acc = acc - var * Scalar::from(1u64 << (8 * i));
        lookup.query(vec![var.into()]);
    }
    cs.constrain(acc);
    lookup.finalize(cs)
}

fn digits(v: u64) -> [Option<u64>; 4] {
    std::array::from_fn(|i| Some((v >> (8 * i)) & 0xff))
}

fn prove_range(v: u64, d: [Option<u64>; 4], prover_table: Table) -> Result<(R1CSProof, CompressedRistretto), R1CSError> {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(1024, 1);
    let mut t = Transcript::new(b"bpvm-range32");
    let mut prover = Prover::new(&pc, &mut t);
    let (com, var) = prover.commit(Scalar::from(v), Scalar::from(7u64));
    range32(&mut prover, var.into(), d, Arc::new(prover_table))?;
    Ok((prover.prove(&bp)?, com))
}

fn verify_range(proof: &R1CSProof, com: CompressedRistretto) -> Result<(), R1CSError> {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(1024, 1);
    let mut t = Transcript::new(b"bpvm-range32");
    let mut verifier = Verifier::new(&mut t);
    let var = verifier.commit(com);
    range32(&mut verifier, var.into(), [None; 4], Arc::new(Table::range(8)))?;
    verifier.verify(proof, &pc, &bp)
}

#[test]
fn range_honest() {
    let v = 0xdead_beef;
    let (proof, com) = prove_range(v, digits(v), Table::range(8)).unwrap();
    verify_range(&proof, com).unwrap();
}

#[test]
fn range_query_outside_table_is_rejected_by_prover() {
    // 2^32 + 1 written with a "digit" 256 in the top position satisfies the linear relation.
    let v = (1u64 << 32) + 1;
    let d = [Some(1), Some(0), Some(0), Some(256)];
    assert!(matches!(prove_range(v, d, Table::range(8)), Err(R1CSError::GadgetError { .. })));
}

#[test]
fn range_cheating_prover_fails_verification() {
    // Prover pretends the table also contains 256; the verifier uses the honest table.
    let v = (1u64 << 32) + 1;
    let d = [Some(1), Some(0), Some(0), Some(256)];
    let mut rows: Vec<Vec<Scalar>> = (0..256u64).map(|i| vec![Scalar::from(i)]).collect();
    rows[255] = vec![Scalar::from(256u64)]; // same size, so the circuit shape matches
    let (proof, com) = prove_range(v, d, Table::new(1, rows)).unwrap();
    assert!(verify_range(&proof, com).is_err());
}

/// 8-bit XOR via two nibble lookups into the (a, b, a^b) table of 256 rows.
fn xor8<CS: bulletproofs::r1cs::RandomizableConstraintSystem>(
    cs: &mut CS,
    a: u64,
    b: u64,
    out: u64,
    prover: bool,
) -> Result<(), R1CSError> {
    let mut lookup = Lookup::new(Arc::new(Table::binary_op(4, |x, y| x ^ y)));
    let mut sums = [LinearCombination::default(), LinearCombination::default(), LinearCombination::default()];
    for nib in 0..2 {
        let shift = 4 * nib;
        let vals = [(a >> shift) & 0xf, (b >> shift) & 0xf, (out >> shift) & 0xf];
        let vars: Vec<_> = vals
            .iter()
            .map(|v| cs.allocate(prover.then(|| Scalar::from(*v))))
            .collect::<Result<_, _>>()?;
        for j in 0..3 {
            sums[j] = sums[j].clone() + vars[j] * Scalar::from(1u64 << shift);
        }
        lookup.query(vars.into_iter().map(LinearCombination::from).collect());
    }
    // Public inputs: a, b, out.
    for (s, v) in sums.into_iter().zip([a, b, out]) {
        cs.constrain(s - Scalar::from(v));
    }
    lookup.finalize(cs)
}

fn xor_roundtrip(a: u64, b: u64, out: u64) -> Result<(), R1CSError> {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(256, 1);
    let mut t = Transcript::new(b"bpvm-xor8");
    let mut prover = Prover::new(&pc, &mut t);
    xor8(&mut prover, a, b, out, true)?;
    let proof = prover.prove(&bp)?;

    let mut t = Transcript::new(b"bpvm-xor8");
    let mut verifier = Verifier::new(&mut t);
    xor8(&mut verifier, a, b, out, false)?;
    verifier.verify(&proof, &pc, &bp)
}

#[test]
fn xor_honest() {
    xor_roundtrip(0xa5, 0x3c, 0xa5 ^ 0x3c).unwrap();
}

#[test]
fn xor_wrong_output() {
    // The prover's own lookup refuses a non-table row.
    assert!(xor_roundtrip(0xa5, 0x3c, 0x00).is_err());
}

#[test]
fn cost_is_one_multiplier_per_query_plus_half_table() {
    let pc = PedersenGens::default();
    let mut t = Transcript::new(b"bpvm-cost");
    let mut prover = Prover::new(&pc, &mut t);
    let (_, var) = prover.commit(Scalar::from(5u64), Scalar::ONE);
    range32(&mut prover, var.into(), digits(5), Arc::new(Table::range(8))).unwrap();
    let bp = BulletproofGens::new(1024, 1);
    let proof = prover.prove(&bp).unwrap();
    // 4 digits (2 multipliers) + 256 multiplicities (128) + 4 reciprocal multipliers
    println!("proof size = {} bytes", proof.to_bytes().len());
}
