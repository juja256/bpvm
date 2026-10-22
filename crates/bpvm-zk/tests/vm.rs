//! End-to-end: execute hand-assembled programs, prove, verify; tampered traces must fail.
//! Run with `cargo test --release` (debug-mode proving is slow).

use std::collections::BTreeMap;

use bpvm_emu::asm::*;
use bpvm_emu::{Image, Machine, Trace};
use bpvm_zk::Backend;

const DATA: u32 = 0x1000;

fn image(code: &[u32], data_words: usize) -> Image {
    let mut img = Image { entry: 0, code: BTreeMap::new(), data: BTreeMap::new(), io: Vec::new(), stack: None };
    for (i, w) in code.iter().enumerate() {
        img.code.insert(4 * i as u32, *w);
    }
    for i in 0..data_words {
        img.data.insert(DATA + 4 * i as u32, 0x8180_7f01u32.wrapping_mul(i as u32 + 1));
    }
    img
}

fn exec(img: &Image) -> Trace {
    Machine::from_image(img).run(1 << 16).expect("program halts")
}

const BACKENDS: [Backend; 2] = [Backend::Bp, Backend::Bppp];

/// Prove and verify with both backends.
fn prove_and_verify(img: &Image, trace: &Trace) -> Result<(), String> {
    let (stmt, wit) = bpvm_zk::witness(img, trace)?;
    for backend in BACKENDS {
        let (proof, stats) = bpvm_zk::prove(&stmt, &wit, backend).map_err(|e| format!("{backend:?}: {e:?}"))?;
        assert_eq!(proof.backend(), backend);
        println!("{backend:?}: {} steps, {} gates, {} linear, {} B, {:.2?}", stmt.steps, stats.gates, stats.linear, stats.proof_bytes, stats.time);
        bpvm_zk::verify(&stmt, &proof).map_err(|e| format!("{backend:?}: {e:?}"))?;
    }
    Ok(())
}

const EDGE: &[u32] = &[0, 1, 7, 0xffff_fff9, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1234_5678];

/// All R-type ALU ops (base + M) on edge-case pairs, results folded into a0 with xor.
#[test]
fn alu_reg_reg() {
    let ops: &[(u32, u32)] = &[
        (0, 0), (0x20, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0x20, 5), (0, 6), (0, 7),
        (1, 0), (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7),
    ];
    let mut code = vec![];
    for &(f7, f3) in ops {
        for (i, &a) in EDGE.iter().enumerate() {
            let b = EDGE[(i * 3 + 1) % EDGE.len()];
            code.extend(li(5, a));
            code.extend(li(6, b));
            code.push(op_r(f7, f3, 7, 5, 6));
            code.push(xor(10, 10, 7));
        }
    }
    code.extend(halt());
    let img = image(&code, 0);
    prove_and_verify(&img, &exec(&img)).unwrap();
}

/// Division corner cases: by zero, signed overflow, negative operands.
#[test]
fn division_corners() {
    let pairs: &[(u32, u32)] = &[(7, 0), (0x8000_0000, 0xffff_ffff), (0xffff_fff9, 2), (7, 0xffff_fffe), (0, 5), (5, 5)];
    let mut code = vec![];
    for &(a, b) in pairs {
        code.extend(li(5, a));
        code.extend(li(6, b));
        for f3 in 4..8 {
            code.push(op_r(1, f3, 7, 5, 6));
            code.push(add(10, 10, 7));
        }
    }
    code.extend(halt());
    let img = image(&code, 0);
    prove_and_verify(&img, &exec(&img)).unwrap();
}

/// Immediate ALU ops including shifts by 0 and 31.
#[test]
fn alu_imm() {
    let mut code = vec![];
    for &a in EDGE {
        code.extend(li(5, a));
        for (f3, imm) in [(0, -1), (2, -5), (3, -5), (4, 0x7ff), (6, -2048), (7, 0x0f0), (1, 0), (1, 31), (5, 31), (5, 0x400 | 31), (5, 0x400)] {
            code.push(op_i(f3, 7, 5, imm));
            code.push(add(10, 10, 7));
        }
        // register shifts use only the low 5 bits of rs2
        code.extend(li(6, 0xffff_ffe3));
        for (f7, f3) in [(0, 1), (0, 5), (0x20, 5)] {
            code.push(op_r(f7, f3, 7, 5, 6));
            code.push(add(10, 10, 7));
        }
    }
    code.extend(halt());
    let img = image(&code, 0);
    prove_and_verify(&img, &exec(&img)).unwrap();
}

/// Byte/half/word loads and stores at every offset, with sign extension.
#[test]
fn memory_widths() {
    let mut code = vec![];
    code.extend(li(5, DATA));
    code.extend(li(6, 0xfedc_ba98));
    for off in 0..4 {
        code.push(store(0, 6, 5, 16 + off)); // sb
        code.push(load(0, 7, 5, off)); // lb
        code.push(add(10, 10, 7));
        code.push(load(4, 7, 5, off)); // lbu
        code.push(add(10, 10, 7));
    }
    for off in [0, 2] {
        code.push(store(1, 6, 5, 20 + off)); // sh
        code.push(load(1, 7, 5, 4 + off)); // lh
        code.push(add(10, 10, 7));
        code.push(load(5, 7, 5, 4 + off)); // lhu
        code.push(add(10, 10, 7));
    }
    code.push(sw(6, 5, 24));
    code.push(lw(7, 5, 16)); // reads back the bytes stored above
    code.push(add(10, 10, 7));
    code.push(lw(7, 5, 20));
    code.push(add(10, 10, 7));
    code.extend(halt());
    let img = image(&code, 8);
    prove_and_verify(&img, &exec(&img)).unwrap();
}

/// Every branch type taken and not taken, jal/jalr forward and backward, auipc.
#[test]
fn control_flow() {
    let mut code = vec![];
    code.extend(li(5, 0xffff_fff9)); // -7
    code.extend(li(6, 3));
    for f3 in [0, 1, 4, 5, 6, 7] {
        for (x, y) in [(5, 6), (6, 5), (5, 5)] {
            code.push(branch(f3, x, y, 8)); // skip next if taken
            code.push(addi(10, 10, 1));
        }
    }
    let n = code.len() as i32;
    code.push(auipc(8, 0)); // x8 = pc
    code.push(jal(1, 12)); // -> call
    code.push(addi(10, 10, 100)); // after return
    code.push(jal(0, 12)); // -> end
    code.push(addi(10, 10, 1000)); // call: (target of jal at n+1)
    code.push(jalr(0, 1, 0)); // return to n+2
    let _ = n;
    code.extend(halt());
    let img = image(&code, 0);
    let t = exec(&img);
    prove_and_verify(&img, &t).unwrap();
}

#[test]
fn fib_elf() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib/fib.elf");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: build guest/fib/fib.elf with `make -C guest`");
        return;
    };
    let img = Image::from_elf(&bytes).unwrap();
    let t = exec(&img);
    assert_eq!(t.exit_code, 55);
    prove_and_verify(&img, &t).unwrap();
}

/// `guest/balance/balance.elf`: private inputs and outputs behind Pedersen commitments.
#[test]
fn committed_io() {
    use bpvm_emu::IoKind;
    use bpvm_zk::{IoSpec, Statement};
    use curve25519_dalek::scalar::Scalar;

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/balance/balance.elf");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: build guest/balance/balance.elf with `make -C guest`");
        return;
    };
    let mut img = Image::from_elf(&bytes).unwrap();
    let values = [("inputs", vec![1000, 2500]), ("outputs", vec![3000, 490]), ("fee", vec![10]), ("max_output", vec![5000])];
    let mut spec = IoSpec::default();
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
                IoKind::PrivateInput => spec.private_in.push((var.words(i), Scalar::from(blind))),
                IoKind::PrivateOutput => spec.private_out.push((var.words(i), Scalar::from(blind))),
                IoKind::PublicOutput => spec.public_out.extend(var.words(i)),
                IoKind::PublicInput => {}
            }
        }
    }
    let t = exec(&img);
    assert_eq!(t.exit_code, 0);
    let (st, wit) = bpvm_zk::witness_with_io(&img, &t, &spec).unwrap();
    assert_eq!((st.private_in.len(), st.private_out.len()), (4, 1));
    assert_eq!(wit.openings()[4].0, 3500, "total");
    // The public statement does not contain the private input values.
    let hidden: Vec<u32> = st.private_in.iter().flat_map(|c| c.words.clone()).collect();
    assert!(st.ram.iter().filter(|(a, _)| hidden.contains(a)).all(|(_, v)| *v == 0));

    for backend in BACKENDS {
        let (proof, _) = bpvm_zk::prove(&st, &wit, backend).unwrap();
        bpvm_zk::verify(&st, &proof).unwrap();

        let reject = |f: &dyn Fn(&mut Statement)| {
            let mut forged = st.clone();
            f(&mut forged);
            assert!(bpvm_zk::verify(&forged, &proof).is_err());
        };
        reject(&|s| s.private_in.swap(0, 1));
        reject(&|s| s.private_out[0].commitment = s.private_in[0].commitment);
        reject(&|s| s.public_out[0].1 = 0);
    }
}

// ---- soundness: a tampered trace yields a proof that does not verify ----

fn small_program() -> Image {
    let mut code = vec![];
    code.extend(li(5, DATA));
    code.extend(li(6, 0x8000_0001));
    code.push(sw(6, 5, 0));
    code.push(lw(7, 5, 0));
    code.push(add(8, 7, 6)); // wraps
    code.push(div(9, 8, 6));
    code.push(bne(8, 0, 8));
    code.push(addi(10, 0, 1));
    code.push(add(10, 10, 9));
    code.extend(halt());
    image(&code, 4)
}

fn assert_rejected(tamper: impl FnOnce(&mut Trace)) {
    let img = small_program();
    let mut t = exec(&img);
    prove_and_verify(&img, &t).expect("honest trace verifies");
    tamper(&mut t);
    let (stmt, wit) = match bpvm_zk::witness(&img, &t) {
        // every tamper here must reach the verifier; one caught earlier tests nothing
        Err(e) => panic!("rejected by witness generation, the verifier is not reached: {e}"),
        Ok(x) => x,
    };
    for backend in BACKENDS {
        // Cheat: the prover skips its own checks (lookups equal to no row, unsatisfied
        // circuits) and must still produce a proof, which the verifier must reject.
        bulletproofs::r1cs::cheats::set_unchecked_prover(true);
        let proved = bpvm_zk::prove(&stmt, &wit, backend);
        bulletproofs::r1cs::cheats::set_unchecked_prover(false);
        let (proof, _) = proved.unwrap_or_else(|e| panic!("{backend:?}: the unchecked prover refused: {e:?}"));
        let r = bpvm_zk::verify(&stmt, &proof);
        eprintln!("{backend:?} verifier: {r:?}");
        assert!(r.is_err(), "{backend:?}: tampered trace verified");
    }
}

fn step_of(t: &mut Trace, pred: impl Fn(&bpvm_emu::Instr) -> bool) -> &mut bpvm_emu::Step {
    t.steps.iter_mut().find(|s| pred(&s.instr)).unwrap()
}

#[test]
fn reject_wrong_add() {
    assert_rejected(|t| step_of(t, |i| matches!(i, bpvm_emu::Instr::Op { op: bpvm_emu::AluOp::Add, .. })).result ^= 1);
}

#[test]
fn reject_wrong_div() {
    assert_rejected(|t| step_of(t, |i| matches!(i, bpvm_emu::Instr::Op { op: bpvm_emu::AluOp::Div, .. })).result += 1);
}

#[test]
fn reject_wrong_load() {
    assert_rejected(|t| step_of(t, |i| matches!(i, bpvm_emu::Instr::Load { .. })).result ^= 0x100);
}

#[test]
fn reject_wrong_branch() {
    // Pretend the bne fell through: next_pc and the following pc both point to the skipped addi.
    assert_rejected(|t| {
        let k = t.steps.iter().position(|s| matches!(s.instr, bpvm_emu::Instr::Branch { .. })).unwrap();
        let fall = t.steps[k].pc + 4;
        t.steps[k].next_pc = fall;
        t.steps[k + 1].pc = fall;
    });
}

#[test]
fn reject_skipped_step() {
    assert_rejected(|t| {
        t.steps.remove(3);
    });
}

/// Only the fetch lookup sees this: the statement's program differs from the executed one in
/// the immediate of an executed instruction, and the witness (so every chip and the bus) is
/// that of the executed program. The honest prover refuses (a fetch equal to no row); an
/// unchecked prover's proof must not verify. Also binds the proof to the table's contents.
#[test]
fn reject_program_other_than_executed() {
    let img = small_program();
    let t = exec(&img);
    let (mut stmt, wit) = bpvm_zk::witness(&img, &t).unwrap();
    let pc = t.steps.iter().find(|s| bpvm_zk::isa::canon(s.instr).is_some_and(|f| f.op == bpvm_zk::isa::Op::ADDI)).expect("an executed addi").pc;
    let row = stmt.program.iter_mut().find(|r| r.pc == pc).unwrap();
    row.fields.imm ^= 0x10;
    for backend in BACKENDS {
        assert!(bpvm_zk::prove(&stmt, &wit, backend).is_err(), "{backend:?}: the honest prover proved a fetch equal to no row");
        bulletproofs::r1cs::cheats::set_unchecked_prover(true);
        let proved = bpvm_zk::prove(&stmt, &wit, backend);
        bulletproofs::r1cs::cheats::set_unchecked_prover(false);
        let (proof, _) = proved.unwrap();
        assert!(bpvm_zk::verify(&stmt, &proof).is_err(), "{backend:?}: a program other than the executed one verified");
    }
}

// ---- the SHA-256 transcript (a verifier with SHA-256 only, such as Simplicity) ----

/// The same program proven under SHA-256 Fiat–Shamir on both backends: the proof verifies
/// under SHA-256 only, and the proof size does not change.
#[test]
fn sha256_transcript_proofs() {
    use bpvm_zk::TranscriptKind;
    let img = small_program();
    let t = exec(&img);
    let (stmt, wit) = bpvm_zk::witness(&img, &t).unwrap();
    for backend in BACKENDS {
        let (proof, stats) = bpvm_zk::prove_with(&stmt, &wit, backend, TranscriptKind::Sha256).unwrap();
        let (merlin_proof, merlin_stats) = bpvm_zk::prove(&stmt, &wit, backend).unwrap();
        assert_eq!(stats.proof_bytes, merlin_stats.proof_bytes);
        bpvm_zk::verify_with(&stmt, &proof, TranscriptKind::Sha256).unwrap();
        assert!(bpvm_zk::verify(&stmt, &proof).is_err(), "{backend:?}: a SHA-256 proof verified under Merlin");
        assert!(bpvm_zk::verify_with(&stmt, &merlin_proof, TranscriptKind::Sha256).is_err(), "{backend:?}: a Merlin proof verified under SHA-256");
        let mut forged = stmt.clone();
        forged.exit_code ^= 1;
        assert!(bpvm_zk::verify_with(&forged, &proof, TranscriptKind::Sha256).is_err(), "{backend:?}: forged exit code");
    }
    assert_eq!("sha256".parse::<TranscriptKind>().unwrap(), TranscriptKind::Sha256);
    assert_eq!(TranscriptKind::default(), TranscriptKind::Merlin);
    assert_eq!(TranscriptKind::Sha256.name(), "sha256");
}

/// The same program over secp256k1 with the SHA-256 transcript (feature `secp256k1`): both
/// backends prove and verify; a forged exit code is rejected.
#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_sha256_proofs() {
    use bpvm_zk::TranscriptKind;
    use bulletproofs::curve::Secp256k1;
    let img = small_program();
    let t = exec(&img);
    let (stmt, wit) = bpvm_zk::witness_for::<Secp256k1>(&img, &t).unwrap();
    for backend in BACKENDS {
        let (proof, stats) = bpvm_zk::prove_with(&stmt, &wit, backend, TranscriptKind::Sha256).unwrap();
        println!("secp256k1 {backend:?}: {} gates, {} B", stats.gates, stats.proof_bytes);
        bpvm_zk::verify_with(&stmt, &proof, TranscriptKind::Sha256).unwrap();
        let mut forged = stmt.clone();
        forged.exit_code ^= 1;
        assert!(bpvm_zk::verify_with(&forged, &proof, TranscriptKind::Sha256).is_err());
        assert!(bpvm_zk::verify_with(&stmt, &proof, TranscriptKind::Merlin).is_err());
    }
}

/// The Simplicity verifier of a guest proof compiles, and its witness is built from the proof
/// (feature `simplicity`; [`simplicity_verifier_runs`] runs it).
#[cfg(feature = "simplicity")]
#[test]
fn simplicity_verifier_compiles() {
    use bulletproofs::curve::Secp256k1;
    use bulletproofs::simplicity::{dummy_env, sighash_of};
    let img = small_program();
    let t = exec(&img);
    let (stmt, wit) = bpvm_zk::witness_for::<Secp256k1>(&img, &t).unwrap();
    let (proof, _) = bpvm_zk::vm::simplicity::prove(&stmt, &wit, &sighash_of(&dummy_env())).unwrap();
    let sv = bpvm_zk::vm::simplicity::compile(&stmt).unwrap();
    assert!(sv.witness(&proof).is_ok());
    println!("simplicity verifier: {:?}", sv.stats().msm_terms);
}

/// The Simplicity verifier accepts an honest proof as a node runs it, and rejects a proof for
/// another transaction. A cost over the budget or the cell limit is reported only after every
/// check has passed, so it counts as accepting here.
#[cfg(feature = "simplicity")]
#[test]
fn simplicity_verifier_runs() {
    use bulletproofs::curve::Secp256k1;
    use bulletproofs::simplicity::{dummy_env, dummy_env_with_output, sighash_of, ExecError};
    let img = small_program();
    let t = exec(&img);
    let (stmt, wit) = bpvm_zk::witness_for::<Secp256k1>(&img, &t).unwrap();
    let env = dummy_env();
    let sv = bpvm_zk::vm::simplicity::compile(&stmt).unwrap();
    let accepted = |r: Result<bulletproofs::simplicity::Report, ExecError>| match r {
        Ok(_) | Err(ExecError::Budget { .. }) | Err(ExecError::Cells(_)) => true,
        Err(e) => {
            println!("rejected: {e:?}");
            false
        }
    };
    let (proof, _) = bpvm_zk::vm::simplicity::prove(&stmt, &wit, &sighash_of(&env)).unwrap();
    assert!(accepted(sv.execute(&sv.witness(&proof).unwrap(), &env)), "an honest proof");
    let (other, _) = bpvm_zk::vm::simplicity::prove(&stmt, &wit, &sighash_of(&dummy_env_with_output(7))).unwrap();
    assert!(!accepted(sv.execute(&sv.witness(&other).unwrap(), &env)), "a proof for another transaction");
}

/// A guest ELF from `guest/`, its inputs set from `values` (name, elements), and the I/O spec
/// of its committed values (blindings 2, 3, ...).
fn guest_with_io<F: bulletproofs::curve::Field + From<u64>>(elf: &str, values: &[(&str, Vec<u64>)]) -> (Image, bpvm_zk::IoSpec<F>) {
    use bpvm_emu::IoKind;
    let path = format!("{}/../../guest/{}", env!("CARGO_MANIFEST_DIR"), elf);
    let mut img = Image::from_elf(&std::fs::read(&path).expect("a committed guest ELF")).unwrap();
    let mut spec = bpvm_zk::IoSpec { private_in: vec![], private_out: vec![], public_out: vec![] };
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
                IoKind::PrivateInput => spec.private_in.push((var.words(i), F::from(blind))),
                IoKind::PrivateOutput => spec.private_out.push((var.words(i), F::from(blind))),
                IoKind::PublicOutput => spec.public_out.extend(var.words(i)),
                IoKind::PublicInput => {}
            }
        }
    }
    (img, spec)
}

/// The factors of `guest/mul`: a = 100 003 and b = 70 001, whose product passes 2^32.
const MUL_IN: [(&str, u64); 2] = [("a", 100_003), ("b", 70_001)];

/// The public output `c` of a statement (little-endian words).
fn public_u64<C: bulletproofs::curve::Curve>(st: &bpvm_zk::Statement<C>) -> u64 {
    st.public_out.iter().enumerate().map(|(k, (_, w))| (*w as u64) << (32 * k)).sum()
}

/// `guest/mul/mul.elf`: c = a · b with a and b private (Pedersen commitments) and c public.
#[test]
fn mul_guest() {
    use bpvm_zk::Statement;
    use curve25519_dalek::scalar::Scalar;
    let values: Vec<(&str, Vec<u64>)> = MUL_IN.iter().map(|(n, v)| (*n, vec![*v])).collect();
    let (img, spec) = guest_with_io::<Scalar>("mul/mul.elf", &values);
    let t = exec(&img);
    assert_eq!(t.exit_code, 0);
    let (st, wit) = bpvm_zk::witness_with_io(&img, &t, &spec).unwrap();
    assert_eq!(st.private_in.len(), 2);
    assert_eq!(public_u64(&st), 100_003 * 70_001);
    // a 16-byte stack, timestamps of 8 bits (18 steps), the 8 registers the program names
    let c = bpvm_zk::cost(&st).unwrap();
    assert_eq!((c.gates(Backend::Bppp), c.linear(Backend::Bppp)), (384, 576), "BP++ gates and linear slots");
    // the public statement does not contain a or b
    let hidden: Vec<u32> = st.private_in.iter().flat_map(|c| c.words.clone()).collect();
    assert!(st.ram.iter().filter(|(a, _)| hidden.contains(a)).all(|(_, v)| *v == 0));
    for backend in BACKENDS {
        let (proof, stats) = bpvm_zk::prove(&st, &wit, backend).unwrap();
        println!("mul {backend:?}: {} steps, {} gates, {} B", st.steps, stats.gates, stats.proof_bytes);
        bpvm_zk::verify(&st, &proof).unwrap();
        let reject = |f: &dyn Fn(&mut Statement)| {
            let mut forged = st.clone();
            f(&mut forged);
            assert!(bpvm_zk::verify(&forged, &proof).is_err());
        };
        reject(&|s| s.public_out[0].1 ^= 1);
        reject(&|s| s.private_in[1].commitment = s.private_in[0].commitment);
    }
}

/// The Simplicity verifier of `guest/mul` accepts its honest proof as a node runs it.
#[cfg(feature = "simplicity")]
#[test]
fn mul_guest_simplicity() {
    use bulletproofs::curve::{Curve, Secp256k1};
    use bulletproofs::simplicity::{dummy_env, sighash_of, ExecError};
    let values: Vec<(&str, Vec<u64>)> = MUL_IN.iter().map(|(n, v)| (*n, vec![*v])).collect();
    let (img, spec) = guest_with_io::<<Secp256k1 as Curve>::Scalar>("mul/mul.elf", &values);
    let t = exec(&img);
    let (st, wit) = bpvm_zk::witness_with_io_for::<Secp256k1>(&img, &t, &spec).unwrap();
    let env = dummy_env();
    let (proof, stats) = bpvm_zk::vm::simplicity::prove(&st, &wit, &sighash_of(&env)).unwrap();
    let sv = bpvm_zk::vm::simplicity::compile(&st).unwrap();
    let r = sv.execute(&sv.witness(&proof).unwrap(), &env);
    println!("mul on Simplicity: {} gates, {} MSM terms: {:?}", stats.gates, sv.stats().msm_terms, r);
    assert!(matches!(r, Ok(_) | Err(ExecError::Budget { .. }) | Err(ExecError::Cells(_))), "{r:?}");
}

/// `n` steps exactly: `addi`s, then the halt.
fn steps_program(n: usize) -> Image {
    let mut code: Vec<u32> = (0..n - 2).map(|i| addi(5, 5, i as i32 % 7)).collect();
    code.extend(halt());
    image(&code, 0)
}

/// Timestamps take 8 bits up to 64 steps (every timestamp at most 4·64 = 256) and 16 from 65:
/// honest traces on both sides of the boundary verify, and the width really changes there.
#[test]
fn timestamp_width_follows_the_steps() {
    assert_eq!((bpvm_zk::gadgets::ts_bits(1), bpvm_zk::gadgets::ts_bits(64), bpvm_zk::gadgets::ts_bits(65)), (8, 8, 16));
    assert_eq!((bpvm_zk::gadgets::ts_bits(1 << 14), bpvm_zk::gadgets::ts_bits((1 << 14) + 1), bpvm_zk::gadgets::ts_bits(1 << 22), bpvm_zk::gadgets::ts_bits((1 << 22) + 1)), (16, 24, 24, 32));
    for n in [63usize, 64, 65, 66] {
        let img = steps_program(n);
        let t = exec(&img);
        assert_eq!(t.steps.len(), n);
        prove_and_verify(&img, &t).unwrap_or_else(|e| panic!("{n} steps: {e}"));
    }
    let gates = |n: usize| {
        let img = steps_program(n);
        let (st, _) = bpvm_zk::witness(&img, &exec(&img)).unwrap();
        bpvm_zk::cost(&st).unwrap().gates(Backend::Bppp)
    };
    // one more digit per register access (3 a step) from 65 steps
    let (a, b, c) = (gates(63), gates(64), gates(65));
    assert!(c - b > (b - a) + 3 * 60, "{a}, {b}, {c}: the width did not change at 65 steps");
}
