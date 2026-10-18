//! End-to-end: execute hand-assembled programs, prove, verify; tampered traces must fail.
//! Run with `cargo test --release` (debug-mode proving is slow).

use std::collections::BTreeMap;

use bpvm_emu::asm::*;
use bpvm_emu::{Image, Machine, Trace};

const DATA: u32 = 0x1000;

fn image(code: &[u32], data_words: usize) -> Image {
    let mut img = Image { entry: 0, code: BTreeMap::new(), data: BTreeMap::new() };
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

fn prove_and_verify(img: &Image, trace: &Trace) -> Result<(), String> {
    let (stmt, wit) = bpvm_zk::witness(img, trace)?;
    let (proof, stats) = bpvm_zk::prove(&stmt, &wit).map_err(|e| format!("{e:?}"))?;
    println!("{} steps, {} multipliers, {:.2?}", stmt.steps, stats.multipliers, stats.time);
    bpvm_zk::verify(&stmt, &proof).map(|_| ()).map_err(|e| format!("{e:?}"))
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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib.elf");
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skipping: build guest/fib.elf with `make -C guest`");
        return;
    };
    let img = Image::from_elf(&bytes).unwrap();
    let t = exec(&img);
    assert_eq!(t.exit_code, 55);
    prove_and_verify(&img, &t).unwrap();
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
    // Cheat: let the prover produce a proof even when its own lookups fail.
    bpvm_zk::logup::set_unchecked_prover(true);
    match bpvm_zk::witness(&img, &t) {
        Err(e) => eprintln!("rejected by witness generation: {e}"),
        Ok((stmt, wit)) => match bpvm_zk::prove(&stmt, &wit) {
            Err(e) => eprintln!("rejected by prover: {e:?}"),
            Ok((proof, _)) => {
                let r = bpvm_zk::verify(&stmt, &proof);
                eprintln!("verifier: {r:?}");
                assert!(r.is_err(), "tampered trace verified");
            }
        },
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
