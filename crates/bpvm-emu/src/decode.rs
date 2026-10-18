//! RV32IM instruction decoding.

/// Register index `x0..x31`.
pub type Reg = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    // M extension
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchOp {
    Eq,
    Ne,
    Lt,
    Ge,
    Ltu,
    Geu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Byte,
    Half,
    Word,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    Lui { rd: Reg, imm: u32 },
    Auipc { rd: Reg, imm: u32 },
    Jal { rd: Reg, imm: i32 },
    Jalr { rd: Reg, rs1: Reg, imm: i32 },
    Branch { op: BranchOp, rs1: Reg, rs2: Reg, imm: i32 },
    Load { width: Width, signed: bool, rd: Reg, rs1: Reg, imm: i32 },
    Store { width: Width, rs1: Reg, rs2: Reg, imm: i32 },
    /// Register-immediate ALU op (`addi`, `slli`, ...). Only base-ISA ops occur here.
    OpImm { op: AluOp, rd: Reg, rs1: Reg, imm: i32 },
    /// Register-register ALU op, including the M extension.
    Op { op: AluOp, rd: Reg, rs1: Reg, rs2: Reg },
    Fence,
    Ecall,
    Ebreak,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError(pub u32);

fn rd(w: u32) -> Reg {
    ((w >> 7) & 0x1f) as Reg
}
fn rs1(w: u32) -> Reg {
    ((w >> 15) & 0x1f) as Reg
}
fn rs2(w: u32) -> Reg {
    ((w >> 20) & 0x1f) as Reg
}
fn funct3(w: u32) -> u32 {
    (w >> 12) & 0x7
}
fn funct7(w: u32) -> u32 {
    w >> 25
}

fn imm_i(w: u32) -> i32 {
    (w as i32) >> 20
}
fn imm_s(w: u32) -> i32 {
    (((w as i32) >> 25) << 5) | ((w >> 7) & 0x1f) as i32
}
fn imm_b(w: u32) -> i32 {
    let sign = ((w as i32) >> 31) << 12;
    let b11 = ((w >> 7) & 1) << 11;
    let b10_5 = ((w >> 25) & 0x3f) << 5;
    let b4_1 = ((w >> 8) & 0xf) << 1;
    sign | (b11 | b10_5 | b4_1) as i32
}
fn imm_u(w: u32) -> u32 {
    w & 0xffff_f000
}
fn imm_j(w: u32) -> i32 {
    let sign = ((w as i32) >> 31) << 20;
    let b19_12 = w & 0x000f_f000;
    let b11 = ((w >> 20) & 1) << 11;
    let b10_1 = ((w >> 21) & 0x3ff) << 1;
    sign | (b19_12 | b11 | b10_1) as i32
}

pub fn decode(w: u32) -> Result<Instr, DecodeError> {
    let err = Err(DecodeError(w));
    Ok(match w & 0x7f {
        0x37 => Instr::Lui { rd: rd(w), imm: imm_u(w) },
        0x17 => Instr::Auipc { rd: rd(w), imm: imm_u(w) },
        0x6f => Instr::Jal { rd: rd(w), imm: imm_j(w) },
        0x67 if funct3(w) == 0 => Instr::Jalr { rd: rd(w), rs1: rs1(w), imm: imm_i(w) },
        0x63 => {
            let op = match funct3(w) {
                0 => BranchOp::Eq,
                1 => BranchOp::Ne,
                4 => BranchOp::Lt,
                5 => BranchOp::Ge,
                6 => BranchOp::Ltu,
                7 => BranchOp::Geu,
                _ => return err,
            };
            Instr::Branch { op, rs1: rs1(w), rs2: rs2(w), imm: imm_b(w) }
        }
        0x03 => {
            let (width, signed) = match funct3(w) {
                0 => (Width::Byte, true),
                1 => (Width::Half, true),
                2 => (Width::Word, true),
                4 => (Width::Byte, false),
                5 => (Width::Half, false),
                _ => return err,
            };
            Instr::Load { width, signed, rd: rd(w), rs1: rs1(w), imm: imm_i(w) }
        }
        0x23 => {
            let width = match funct3(w) {
                0 => Width::Byte,
                1 => Width::Half,
                2 => Width::Word,
                _ => return err,
            };
            Instr::Store { width, rs1: rs1(w), rs2: rs2(w), imm: imm_s(w) }
        }
        0x13 => {
            let imm = imm_i(w);
            let shamt = (imm & 0x1f) as i32;
            let (op, imm) = match (funct3(w), funct7(w)) {
                (0, _) => (AluOp::Add, imm),
                (2, _) => (AluOp::Slt, imm),
                (3, _) => (AluOp::Sltu, imm),
                (4, _) => (AluOp::Xor, imm),
                (6, _) => (AluOp::Or, imm),
                (7, _) => (AluOp::And, imm),
                (1, 0x00) => (AluOp::Sll, shamt),
                (5, 0x00) => (AluOp::Srl, shamt),
                (5, 0x20) => (AluOp::Sra, shamt),
                _ => return err,
            };
            Instr::OpImm { op, rd: rd(w), rs1: rs1(w), imm }
        }
        0x33 => {
            let op = match (funct7(w), funct3(w)) {
                (0x00, 0) => AluOp::Add,
                (0x20, 0) => AluOp::Sub,
                (0x00, 1) => AluOp::Sll,
                (0x00, 2) => AluOp::Slt,
                (0x00, 3) => AluOp::Sltu,
                (0x00, 4) => AluOp::Xor,
                (0x00, 5) => AluOp::Srl,
                (0x20, 5) => AluOp::Sra,
                (0x00, 6) => AluOp::Or,
                (0x00, 7) => AluOp::And,
                (0x01, 0) => AluOp::Mul,
                (0x01, 1) => AluOp::Mulh,
                (0x01, 2) => AluOp::Mulhsu,
                (0x01, 3) => AluOp::Mulhu,
                (0x01, 4) => AluOp::Div,
                (0x01, 5) => AluOp::Divu,
                (0x01, 6) => AluOp::Rem,
                (0x01, 7) => AluOp::Remu,
                _ => return err,
            };
            Instr::Op { op, rd: rd(w), rs1: rs1(w), rs2: rs2(w) }
        }
        0x0f => Instr::Fence,
        0x73 => match w {
            0x0000_0073 => Instr::Ecall,
            0x0010_0073 => Instr::Ebreak,
            _ => return err,
        },
        _ => return err,
    })
}
