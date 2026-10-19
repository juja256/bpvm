//! Opcode ids and the public program table.
//!
//! Every instruction is put in a canonical form $(\mathsf{op}, rd, rs_1, rs_2, \mathsf{imm},
//! \mathsf{wr})$: unused register fields are `x0` (which always reads 0), `imm` is the
//! sign-extended immediate as a `u32`, and `wr = 1` iff the instruction writes a register
//! other than `x0`. The CPU chip fetches this tuple by a lookup keyed by `pc`.

use bpvm_emu::{AluOp, BranchOp, Image, Instr, Width};
use curve25519_dalek::scalar::Scalar;

macro_rules! ops {
    ($($name:ident),* $(,)?) => {
        #[allow(clippy::upper_case_acronyms)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum Op { $($name),* }
        impl Op {
            pub const ALL: &'static [Op] = &[$(Op::$name),*];
        }
    };
}

ops! {
    LUI, AUIPC, JAL, JALR,
    BEQ, BNE, BLT, BGE, BLTU, BGEU,
    LB, LH, LW, LBU, LHU, SB, SH, SW,
    ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI,
    ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND,
    MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU,
    FENCE, ECALL,
}

impl Op {
    pub fn id(self) -> Scalar {
        Scalar::from(self as u8 as u64)
    }
}

/// Canonical instruction fields (see module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub op: Op,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: u32,
    pub wr: bool,
}

pub fn canon(instr: Instr) -> Option<Fields> {
    let f = |op, rd: u8, rs1, rs2, imm: i32| Fields { op, rd, rs1, rs2, imm: imm as u32, wr: false };
    let mut x = match instr {
        Instr::Lui { rd, imm } => f(Op::LUI, rd, 0, 0, imm as i32),
        Instr::Auipc { rd, imm } => f(Op::AUIPC, rd, 0, 0, imm as i32),
        Instr::Jal { rd, imm } => f(Op::JAL, rd, 0, 0, imm),
        Instr::Jalr { rd, rs1, imm } => f(Op::JALR, rd, rs1, 0, imm),
        Instr::Branch { op, rs1, rs2, imm } => {
            let op = match op {
                BranchOp::Eq => Op::BEQ,
                BranchOp::Ne => Op::BNE,
                BranchOp::Lt => Op::BLT,
                BranchOp::Ge => Op::BGE,
                BranchOp::Ltu => Op::BLTU,
                BranchOp::Geu => Op::BGEU,
            };
            f(op, 0, rs1, rs2, imm)
        }
        Instr::Load { width, signed, rd, rs1, imm } => {
            let op = match (width, signed) {
                (Width::Byte, true) => Op::LB,
                (Width::Half, true) => Op::LH,
                (Width::Word, _) => Op::LW,
                (Width::Byte, false) => Op::LBU,
                (Width::Half, false) => Op::LHU,
            };
            f(op, rd, rs1, 0, imm)
        }
        Instr::Store { width, rs1, rs2, imm } => {
            let op = match width {
                Width::Byte => Op::SB,
                Width::Half => Op::SH,
                Width::Word => Op::SW,
            };
            f(op, 0, rs1, rs2, imm)
        }
        Instr::OpImm { op, rd, rs1, imm } => {
            let op = match op {
                AluOp::Add => Op::ADDI,
                AluOp::Slt => Op::SLTI,
                AluOp::Sltu => Op::SLTIU,
                AluOp::Xor => Op::XORI,
                AluOp::Or => Op::ORI,
                AluOp::And => Op::ANDI,
                AluOp::Sll => Op::SLLI,
                AluOp::Srl => Op::SRLI,
                AluOp::Sra => Op::SRAI,
                _ => return None,
            };
            f(op, rd, rs1, 0, imm)
        }
        Instr::Op { op, rd, rs1, rs2 } => {
            let op = match op {
                AluOp::Add => Op::ADD,
                AluOp::Sub => Op::SUB,
                AluOp::Sll => Op::SLL,
                AluOp::Slt => Op::SLT,
                AluOp::Sltu => Op::SLTU,
                AluOp::Xor => Op::XOR,
                AluOp::Srl => Op::SRL,
                AluOp::Sra => Op::SRA,
                AluOp::Or => Op::OR,
                AluOp::And => Op::AND,
                AluOp::Mul => Op::MUL,
                AluOp::Mulh => Op::MULH,
                AluOp::Mulhsu => Op::MULHSU,
                AluOp::Mulhu => Op::MULHU,
                AluOp::Div => Op::DIV,
                AluOp::Divu => Op::DIVU,
                AluOp::Rem => Op::REM,
                AluOp::Remu => Op::REMU,
            };
            f(op, rd, rs1, rs2, 0)
        }
        Instr::Fence => f(Op::FENCE, 0, 0, 0, 0),
        // `ecall` reads a7 (syscall number) and a0 (exit code).
        Instr::Ecall => f(Op::ECALL, 0, 17, 10, 0),
        Instr::Ebreak => return None,
    };
    x.wr = x.rd != 0;
    Some(x)
}

/// One row of the public program table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgRow {
    pub pc: u32,
    pub fields: Fields,
}

impl ProgRow {
    /// The row of the program table: $(\mathsf{pc}, \mathsf{op}, rd, rs_1, rs_2, \mathsf{imm}, \mathsf{wr})$.
    pub fn to_row(&self) -> Vec<u64> {
        let f = &self.fields;
        vec![self.pc as u64, f.op as u8 as u64, f.rd as u64, f.rs1 as u64, f.rs2 as u64, f.imm as u64, f.wr as u64]
    }

    pub fn to_scalars(&self) -> Vec<Scalar> {
        self.to_row().into_iter().map(Scalar::from).collect()
    }
}

pub const PROG_WIDTH: usize = 7;

/// Program table from the executable segments. Words that do not decode to a supported
/// instruction are omitted (fetching them is then unprovable).
pub fn program_table(img: &Image) -> Vec<ProgRow> {
    img.code
        .iter()
        .filter(|(pc, _)| **pc < u32::MAX - 4)
        .filter_map(|(pc, w)| {
            let fields = canon(bpvm_emu::decode(*w).ok()?)?;
            Some(ProgRow { pc: *pc, fields })
        })
        .collect()
}
