//! RV32IM interpreter producing an execution trace.
//!
//! Memory is word-granular: every load/store touches exactly one aligned 32-bit word, and
//! the trace records that word before and after the access. This is the shape the memory
//! consistency argument (offline memory checking via reciprocal sums) consumes.

use std::collections::BTreeMap;

use crate::decode::{decode, AluOp, BranchOp, DecodeError, Instr, Reg, Width};

/// `ecall` with `a7 = 93` halts the machine with exit code `a0` (Linux `exit` number).
pub const SYSCALL_HALT: u32 = 93;

const A0: Reg = 10;
const A7: Reg = 17;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trap {
    Decode { pc: u32, err: DecodeError },
    MisalignedPc(u32),
    MisalignedAccess { pc: u32, addr: u32 },
    UnsupportedEcall { pc: u32, number: u32 },
    Ebreak { pc: u32 },
    StepLimit(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemAccess {
    /// Word-aligned address.
    pub addr: u32,
    pub before: u32,
    pub after: u32,
}

impl MemAccess {
    pub fn is_write(&self) -> bool {
        self.before != self.after
    }
}

/// One executed instruction: everything the step circuit needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub clk: u64,
    pub pc: u32,
    pub word: u32,
    pub instr: Instr,
    /// Register reads `(index, value)` in the order rs1, rs2.
    pub reads: [Option<(Reg, u32)>; 2],
    /// Register write `(index, value)`; writes to `x0` are dropped.
    pub write: Option<(Reg, u32)>,
    /// Value the instruction computes for `rd` (also when `rd = x0`); 0 if it has no `rd`.
    pub result: u32,
    pub mem: Option<MemAccess>,
    pub next_pc: u32,
}

#[derive(Clone, Debug)]
pub struct Trace {
    pub steps: Vec<Step>,
    pub exit_code: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Machine {
    pub pc: u32,
    pub regs: [u32; 32],
    /// Sparse word memory keyed by aligned address. Code lives here too.
    pub mem: BTreeMap<u32, u32>,
    pub clk: u64,
}

impl Machine {
    /// Load `words` at `base` (must be word-aligned) and start executing there.
    pub fn new(base: u32, words: &[u32]) -> Self {
        assert_eq!(base % 4, 0, "program base must be word-aligned");
        let mut m = Machine { pc: base, ..Default::default() };
        for (i, w) in words.iter().enumerate() {
            m.mem.insert(base + 4 * i as u32, *w);
        }
        m
    }

    /// Load an ELF image: code and data share the emulator's memory.
    pub fn from_image(img: &crate::elf::Image) -> Self {
        let mut m = Machine { pc: img.entry, ..Default::default() };
        for (a, w) in img.code.iter().chain(img.data.iter()) {
            m.mem.insert(*a, *w);
        }
        m
    }

    pub fn load_word(&self, addr: u32) -> u32 {
        *self.mem.get(&addr).unwrap_or(&0)
    }

    fn reg(&self, r: Reg) -> u32 {
        self.regs[r as usize]
    }

    /// Run until halt or `max_steps`, recording the trace.
    pub fn run(&mut self, max_steps: u64) -> Result<Trace, Trap> {
        let mut steps = Vec::new();
        loop {
            if steps.len() as u64 >= max_steps {
                return Err(Trap::StepLimit(max_steps));
            }
            match self.step()? {
                (step, None) => steps.push(step),
                (step, Some(exit_code)) => {
                    steps.push(step);
                    return Ok(Trace { steps, exit_code });
                }
            }
        }
    }

    /// Execute one instruction. Returns the step and `Some(exit_code)` on halt.
    pub fn step(&mut self) -> Result<(Step, Option<u32>), Trap> {
        let pc = self.pc;
        if pc % 4 != 0 {
            return Err(Trap::MisalignedPc(pc));
        }
        let word = self.load_word(pc);
        let instr = decode(word).map_err(|err| Trap::Decode { pc, err })?;

        let mut reads = [None, None];
        let mut read = |slot: usize, m: &Machine, r: Reg| {
            let v = m.reg(r);
            reads[slot] = Some((r, v));
            v
        };

        let mut rd_val: Option<(Reg, u32)> = None;
        let mut mem = None;
        let mut next_pc = pc.wrapping_add(4);
        let mut halt = None;

        match instr {
            Instr::Lui { rd, imm } => rd_val = Some((rd, imm)),
            Instr::Auipc { rd, imm } => rd_val = Some((rd, pc.wrapping_add(imm))),
            Instr::Jal { rd, imm } => {
                rd_val = Some((rd, pc.wrapping_add(4)));
                next_pc = pc.wrapping_add(imm as u32);
            }
            Instr::Jalr { rd, rs1, imm } => {
                let a = read(0, self, rs1);
                rd_val = Some((rd, pc.wrapping_add(4)));
                next_pc = a.wrapping_add(imm as u32) & !1;
            }
            Instr::Branch { op, rs1, rs2, imm } => {
                let a = read(0, self, rs1);
                let b = read(1, self, rs2);
                if branch(op, a, b) {
                    next_pc = pc.wrapping_add(imm as u32);
                }
            }
            Instr::Load { width, signed, rd, rs1, imm } => {
                let addr = read(0, self, rs1).wrapping_add(imm as u32);
                check_align(pc, addr, width)?;
                let waddr = addr & !3;
                let w = self.load_word(waddr);
                let shift = (addr & 3) * 8;
                let v = match (width, signed) {
                    (Width::Byte, false) => (w >> shift) & 0xff,
                    (Width::Byte, true) => ((w >> shift) as u8 as i8) as i32 as u32,
                    (Width::Half, false) => (w >> shift) & 0xffff,
                    (Width::Half, true) => ((w >> shift) as u16 as i16) as i32 as u32,
                    (Width::Word, _) => w,
                };
                mem = Some(MemAccess { addr: waddr, before: w, after: w });
                rd_val = Some((rd, v));
            }
            Instr::Store { width, rs1, rs2, imm } => {
                let addr = read(0, self, rs1).wrapping_add(imm as u32);
                let v = read(1, self, rs2);
                check_align(pc, addr, width)?;
                let waddr = addr & !3;
                let before = self.load_word(waddr);
                let shift = (addr & 3) * 8;
                let mask = match width {
                    Width::Byte => 0xffu32,
                    Width::Half => 0xffff,
                    Width::Word => 0xffff_ffff,
                } << shift;
                let after = (before & !mask) | ((v << shift) & mask);
                self.mem.insert(waddr, after);
                mem = Some(MemAccess { addr: waddr, before, after });
            }
            Instr::OpImm { op, rd, rs1, imm } => {
                let a = read(0, self, rs1);
                rd_val = Some((rd, alu(op, a, imm as u32)));
            }
            Instr::Op { op, rd, rs1, rs2 } => {
                let a = read(0, self, rs1);
                let b = read(1, self, rs2);
                rd_val = Some((rd, alu(op, a, b)));
            }
            Instr::Fence => {}
            Instr::Ecall => {
                let number = read(0, self, A7);
                let code = read(1, self, A0);
                if number != SYSCALL_HALT {
                    return Err(Trap::UnsupportedEcall { pc, number });
                }
                halt = Some(code);
                next_pc = pc;
            }
            Instr::Ebreak => return Err(Trap::Ebreak { pc }),
        }

        let result = rd_val.map_or(0, |(_, v)| v);
        let write = rd_val.filter(|(rd, _)| *rd != 0);
        if let Some((rd, v)) = write {
            self.regs[rd as usize] = v;
        }
        let step = Step { clk: self.clk, pc, word, instr, reads, write, result, mem, next_pc };
        self.clk += 1;
        self.pc = next_pc;
        Ok((step, halt))
    }
}

fn check_align(pc: u32, addr: u32, width: Width) -> Result<(), Trap> {
    let a = match width {
        Width::Byte => 1,
        Width::Half => 2,
        Width::Word => 4,
    };
    if addr % a != 0 {
        return Err(Trap::MisalignedAccess { pc, addr });
    }
    Ok(())
}

pub fn branch(op: BranchOp, a: u32, b: u32) -> bool {
    match op {
        BranchOp::Eq => a == b,
        BranchOp::Ne => a != b,
        BranchOp::Lt => (a as i32) < (b as i32),
        BranchOp::Ge => (a as i32) >= (b as i32),
        BranchOp::Ltu => a < b,
        BranchOp::Geu => a >= b,
    }
}

/// RV32IM ALU semantics, including the spec-mandated results for division by zero and
/// signed overflow (no traps).
pub fn alu(op: AluOp, a: u32, b: u32) -> u32 {
    let (sa, sb) = (a as i32, b as i32);
    match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::Sll => a << (b & 31),
        AluOp::Slt => (sa < sb) as u32,
        AluOp::Sltu => (a < b) as u32,
        AluOp::Xor => a ^ b,
        AluOp::Srl => a >> (b & 31),
        AluOp::Sra => (sa >> (b & 31)) as u32,
        AluOp::Or => a | b,
        AluOp::And => a & b,
        AluOp::Mul => a.wrapping_mul(b),
        AluOp::Mulh => ((sa as i64 * sb as i64) >> 32) as u32,
        AluOp::Mulhsu => ((sa as i64 * b as i64) >> 32) as u32,
        AluOp::Mulhu => ((a as u64 * b as u64) >> 32) as u32,
        AluOp::Div => {
            if b == 0 {
                u32::MAX
            } else {
                sa.wrapping_div(sb) as u32
            }
        }
        AluOp::Divu => {
            if b == 0 {
                u32::MAX
            } else {
                a / b
            }
        }
        AluOp::Rem => {
            if b == 0 {
                a
            } else {
                sa.wrapping_rem(sb) as u32
            }
        }
        AluOp::Remu => {
            if b == 0 {
                a
            } else {
                a % b
            }
        }
    }
}
