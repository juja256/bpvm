use bpvm_emu::asm::*;
use bpvm_emu::cpu::alu;
use bpvm_emu::{decode, AluOp, Instr, Machine, Trap};

fn run(prog: &[u32]) -> bpvm_emu::Trace {
    Machine::new(0, prog).run(10_000).expect("program should halt")
}

#[test]
fn decode_immediates() {
    assert_eq!(decode(addi(1, 2, -1)).unwrap(), Instr::OpImm { op: AluOp::Add, rd: 1, rs1: 2, imm: -1 });
    assert_eq!(
        decode(srai(3, 4, 7)).unwrap(),
        Instr::OpImm { op: AluOp::Sra, rd: 3, rs1: 4, imm: 7 }
    );
    for imm in [-4096, -2, 2, 4094] {
        match decode(beq(1, 2, imm)).unwrap() {
            Instr::Branch { imm: got, .. } => assert_eq!(got, imm),
            other => panic!("{other:?}"),
        }
    }
    for imm in [-(1 << 20), -2, 2, (1 << 20) - 2] {
        match decode(jal(1, imm)).unwrap() {
            Instr::Jal { imm: got, .. } => assert_eq!(got, imm),
            other => panic!("{other:?}"),
        }
    }
    for imm in [-2048, -1, 0, 2047] {
        match decode(sw(5, 6, imm)).unwrap() {
            Instr::Store { imm: got, .. } => assert_eq!(got, imm),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn fibonacci() {
    let mut prog = vec![
        addi(5, 0, 10), // n
        addi(6, 0, 0),  // a
        addi(7, 0, 1),  // b
        beq(5, 0, 24),  // loop: if n == 0 goto end
        add(28, 6, 7),
        addi(6, 7, 0),
        addi(7, 28, 0),
        addi(5, 5, -1),
        jal(0, -20), // goto loop
        addi(10, 6, 0), // end: a0 = a
    ];
    prog.extend(halt());
    let t = run(&prog);
    assert_eq!(t.exit_code, 55);
    assert_eq!(t.steps.len(), 3 + 10 * 6 + 1 + 3);
    // clk is the step index and next_pc chains
    for (k, w) in t.steps.windows(2).enumerate() {
        assert_eq!(w[0].clk, k as u64);
        assert_eq!(w[0].next_pc, w[1].pc);
    }
}

#[test]
fn memory_bytes_and_words() {
    let mut prog = vec![
        lui(5, 0x1),          // x5 = 0x1000
        addi(6, 0, -128),     // x6 = 0xffffff80
        sb(6, 5, 1),          // mem[0x1001] = 0x80
        lb(7, 5, 1),          // x7 = sext(0x80) = -128
        lbu(8, 5, 1),         // x8 = 0x80
        lw(9, 5, 0),          // x9 = 0x00008000
        sub(10, 8, 7),        // a0 = 0x80 - (-128) = 256
        add(10, 10, 9),       // a0 += 0x8000
    ];
    prog.extend(halt());
    let t = run(&prog);
    assert_eq!(t.exit_code, 256 + 0x8000);

    let store = t.steps[2].mem.unwrap();
    assert_eq!((store.addr, store.before, store.after), (0x1000, 0, 0x8000));
    assert!(store.is_write());
    let load = t.steps[5].mem.unwrap();
    assert_eq!((load.addr, load.before, load.after), (0x1000, 0x8000, 0x8000));
}

#[test]
fn x0_is_hardwired() {
    let mut prog = vec![addi(0, 0, 5), addi(10, 0, 0)];
    prog.extend(halt());
    let t = run(&prog);
    assert_eq!(t.exit_code, 0);
    assert_eq!(t.steps[0].write, None);
}

#[test]
fn m_extension_edge_cases() {
    let min = i32::MIN as u32;
    assert_eq!(alu(AluOp::Div, 7, 0), u32::MAX);
    assert_eq!(alu(AluOp::Divu, 7, 0), u32::MAX);
    assert_eq!(alu(AluOp::Rem, 7, 0), 7);
    assert_eq!(alu(AluOp::Div, min, u32::MAX), min);
    assert_eq!(alu(AluOp::Rem, min, u32::MAX), 0);
    assert_eq!(alu(AluOp::Div, (-7i32) as u32, 2), (-3i32) as u32);
    assert_eq!(alu(AluOp::Rem, (-7i32) as u32, 2), (-1i32) as u32);
    assert_eq!(alu(AluOp::Mulh, u32::MAX, u32::MAX), 0); // (-1)*(-1) = 1
    assert_eq!(alu(AluOp::Mulhu, u32::MAX, u32::MAX), 0xffff_fffe);
    assert_eq!(alu(AluOp::Mulhsu, u32::MAX, u32::MAX), u32::MAX); // -1 * (2^32-1)
}

#[test]
fn traps() {
    assert!(matches!(Machine::new(0, &[0xffff_ffff]).run(10), Err(Trap::Decode { .. })));
    assert!(matches!(Machine::new(0, &[jal(0, 0)]).run(10), Err(Trap::StepLimit(10))));
    assert!(matches!(
        Machine::new(0, &[addi(5, 0, 2), lw(6, 5, 0)]).run(10),
        Err(Trap::MisalignedAccess { addr: 2, .. })
    ));
}

#[test]
fn malformed_elf_is_an_error_not_a_panic() {
    use bpvm_emu::Image;
    let good = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib/fib.elf"));
    let Ok(good) = good else { return };
    assert!(Image::from_elf(&good).is_ok());
    for len in [0, 4, 5, 20, 52, 100, good.len() / 2, good.len() - 1] {
        let _ = Image::from_elf(&good[..len]); // must not panic
    }
    let mut bad = good.clone();
    for i in (0..bad.len()).step_by(7) {
        bad[i] ^= 0xff;
        let _ = Image::from_elf(&bad);
        bad[i] ^= 0xff;
    }
}
