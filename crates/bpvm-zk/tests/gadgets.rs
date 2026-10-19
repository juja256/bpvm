//! Gadgets of `Env` on both backends: range checks and nibble-wise bitwise operations.

use bpvm_zk::gadgets::{lc, s, Env, TAG_AND, TAG_OR, TAG_XOR};
use bpvm_zk::isa::PROG_WIDTH;
use bpvm_zk::Backend;
use bulletproofs::r1cs::{CircuitBuilder, Cost, Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

const BACKENDS: [Backend; 2] = [Backend::Bp, Backend::Bppp];

fn env<CS: CircuitBuilder>(cs: &mut CS) -> Result<Env<'_, CS>, R1CSError> {
    Env::new(cs, vec![vec![0; PROG_WIDTH]])
}

/// `x < 2^bits` with `x` a witness; `value` is the prover's.
fn range<CS: CircuitBuilder>(cs: &mut CS, value: Option<u64>, bits: u32) -> Result<(), R1CSError> {
    let mut e = env(cs)?;
    let x = e.alloc(value)?;
    e.range_bits(x.into(), value, bits)?;
    e.finish()
}

/// `r = a op b` for public 32-bit `a, b, r`; `prover` says whether to assign witnesses.
fn bitop<CS: CircuitBuilder>(cs: &mut CS, tag: u64, a: u32, b: u32, r: u32, prover: bool) -> Result<(), R1CSError> {
    let mut e = env(cs)?;
    e.bitop(tag, lc(s(a as u64)), lc(s(b as u64)), lc(s(r as u64)), prover.then_some((a, b, r)))?;
    e.finish()
}

fn prove(backend: Backend, f: impl FnOnce(&mut Prover<'_, &mut Transcript>) -> Result<(), R1CSError>) -> Result<(R1CSProof, Cost), R1CSError> {
    let pc = PedersenGens::default();
    let mut t = Transcript::new(b"bpvm-gadgets");
    let mut p = Prover::new(&pc, &mut t);
    p.set_backend(backend);
    f(&mut p)?;
    let cost = p.cost();
    let bp = BulletproofGens::new(cost.gens_capacity(backend).next_power_of_two(), 1);
    Ok((p.prove(&bp)?, cost))
}

fn verify(proof: &R1CSProof, f: impl FnOnce(&mut Verifier<&mut Transcript>) -> Result<(), R1CSError>) -> Result<(), R1CSError> {
    let pc = PedersenGens::default();
    let mut t = Transcript::new(b"bpvm-gadgets");
    let mut v = Verifier::new(&mut t);
    v.set_backend(proof.backend());
    f(&mut v)?;
    let bp = BulletproofGens::new(v.cost().gens_capacity(proof.backend()).next_power_of_two(), 1);
    v.verify(proof, &pc, &bp)
}

fn unchecked<T>(f: impl FnOnce() -> T) -> T {
    bulletproofs::r1cs::cheats::set_unchecked_prover(true);
    let r = f();
    bulletproofs::r1cs::cheats::set_unchecked_prover(false);
    r
}

#[test]
fn range_checks_verify() {
    for backend in BACKENDS {
        for (v, bits) in [(0u64, 1), (1, 1), (0xdead_beef, 32), (u32::MAX as u64, 32), ((1 << 24) - 1, 24), (5, 3), (1 << 30, 31)] {
            let (proof, _) = prove(backend, |cs| range(cs, Some(v), bits)).unwrap();
            verify(&proof, |cs| range(cs, None, bits)).unwrap_or_else(|e| panic!("{backend:?} {v} {bits}: {e:?}"));
        }
    }
}

/// Out of range: the digits of `value mod 2^bits` do not add up to `value`, so the proof
/// (the prover does not refuse a violated linear constraint) must not verify.
#[test]
fn out_of_range_values_do_not_verify() {
    for backend in BACKENDS {
        for (v, bits) in [(2u64, 1), (1 << 32, 32), (1 << 24, 24), (8, 3)] {
            let (proof, _) = unchecked(|| prove(backend, |cs| range(cs, Some(v), bits))).unwrap();
            assert!(verify(&proof, |cs| range(cs, None, bits)).is_err(), "{backend:?} {v} {bits}");
        }
    }
}

#[test]
fn bitwise_operations_verify() {
    let (a, b) = (0xa5c3_0ff1u32, 0x3c5a_f00fu32);
    for backend in BACKENDS {
        for (tag, r) in [(TAG_XOR, a ^ b), (TAG_OR, a | b), (TAG_AND, a & b)] {
            let (proof, _) = prove(backend, |cs| bitop(cs, tag, a, b, r, true)).unwrap();
            verify(&proof, |cs| bitop(cs, tag, a, b, r, false)).unwrap();
        }
    }
}

/// A wrong result: some nibble triple is no row of the table. The honest prover refuses; an
/// unchecked prover's proof does not verify.
#[test]
fn wrong_bitwise_results_are_rejected() {
    let (a, b) = (0xa5c3_0ff1u32, 0x3c5a_f00fu32);
    for backend in BACKENDS {
        for (tag, r) in [(TAG_XOR, (a ^ b) ^ 0x10), (TAG_AND, a | b), (TAG_OR, 0)] {
            assert!(prove(backend, |cs| bitop(cs, tag, a, b, r, true)).is_err(), "{backend:?}: honest prover");
            let (proof, _) = unchecked(|| prove(backend, |cs| bitop(cs, tag, a, b, r, true))).unwrap();
            assert!(verify(&proof, |cs| bitop(cs, tag, a, b, r, false)).is_err(), "{backend:?}: a wrong result verified");
        }
    }
}

/// The verifier rebuilds its own circuit: a proof for one width does not verify another.
#[test]
fn proofs_are_bound_to_the_circuit() {
    for backend in BACKENDS {
        let (proof, _) = prove(backend, |cs| range(cs, Some(7), 8)).unwrap();
        assert!(verify(&proof, |cs| range(cs, None, 7)).is_err());
        assert!(verify(&proof, |cs| range(cs, None, 16)).is_err());
    }
}

/// A 32-bit range check: four byte lookups. BP pays a multiplier per lookup and half a
/// multiplier per table row (multiplicities) and per witness; BP++ pays no gate for either.
#[test]
fn costs_of_a_range_check() {
    let (_, bp) = prove(Backend::Bp, |cs| range(cs, Some(1), 32)).unwrap();
    let (_, bppp) = prove(Backend::Bppp, |cs| range(cs, Some(1), 32)).unwrap();
    println!("BP {bp:?}\nBP++ {bppp:?}");
    assert_eq!(bp.bp_phase2, 4, "one multiplier per lookup");
    assert!(bppp.bppp_gates < bp.bp_phase1 + bp.bp_phase2);
}
