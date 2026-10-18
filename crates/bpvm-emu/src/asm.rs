//! Minimal RV32IM encoder for tests and hand-written programs (no labels, no pseudo-ops
//! beyond the ones below). Real guests come from `rustc`/`clang` as ELF.

fn r(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    (funct7 << 25) | ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | (funct3 << 12) | ((rd as u32) << 7) | opcode
}

fn i(imm: i32, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 as u32) << 15) | (funct3 << 12) | ((rd as u32) << 7) | opcode
}

fn s(imm: i32, rs2: u8, rs1: u8, funct3: u32, opcode: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 5) & 0x7f) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | opcode
}

fn b(imm: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}

pub fn lui(rd: u8, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd as u32) << 7) | 0x37
}
pub fn auipc(rd: u8, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd as u32) << 7) | 0x17
}
pub fn jal(rd: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | ((rd as u32) << 7)
        | 0x6f
}
pub fn jalr(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 0, rd, 0x67)
}

pub fn beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, 0)
}
pub fn bne(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, 1)
}
pub fn blt(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, 4)
}
pub fn bge(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, 5)
}
pub fn bltu(rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, 6)
}

pub fn lb(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 0, rd, 0x03)
}
pub fn lh(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 1, rd, 0x03)
}
pub fn lw(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 2, rd, 0x03)
}
pub fn lbu(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 4, rd, 0x03)
}
pub fn sb(rs2: u8, rs1: u8, imm: i32) -> u32 {
    s(imm, rs2, rs1, 0, 0x23)
}
pub fn sw(rs2: u8, rs1: u8, imm: i32) -> u32 {
    s(imm, rs2, rs1, 2, 0x23)
}

pub fn addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 0, rd, 0x13)
}
pub fn xori(rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, 4, rd, 0x13)
}
pub fn slli(rd: u8, rs1: u8, shamt: u32) -> u32 {
    i(shamt as i32, rs1, 1, rd, 0x13)
}
pub fn srai(rd: u8, rs1: u8, shamt: u32) -> u32 {
    i((0x400 | shamt) as i32, rs1, 5, rd, 0x13)
}

pub fn add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(0, rs2, rs1, 0, rd, 0x33)
}
pub fn sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(0x20, rs2, rs1, 0, rd, 0x33)
}
pub fn xor(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(0, rs2, rs1, 4, rd, 0x33)
}
pub fn mul(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(1, rs2, rs1, 0, rd, 0x33)
}
pub fn mulhu(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(1, rs2, rs1, 3, rd, 0x33)
}
pub fn div(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(1, rs2, rs1, 4, rd, 0x33)
}
pub fn rem(rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(1, rs2, rs1, 6, rd, 0x33)
}

pub fn ecall() -> u32 {
    0x0000_0073
}

/// `li a7, 93; ecall` — halt with exit code in `a0`.
pub fn halt() -> [u32; 2] {
    [addi(17, 0, 93), ecall()]
}

/// Any R-type instruction on the OP opcode (`funct7`, `funct3` from the spec).
pub fn op_r(funct7: u32, funct3: u32, rd: u8, rs1: u8, rs2: u8) -> u32 {
    r(funct7, rs2, rs1, funct3, rd, 0x33)
}
/// Any I-type instruction on the OP-IMM opcode; for shifts pass `imm = funct7 << 5 | shamt`.
pub fn op_i(funct3: u32, rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, funct3, rd, 0x13)
}
pub fn load(funct3: u32, rd: u8, rs1: u8, imm: i32) -> u32 {
    i(imm, rs1, funct3, rd, 0x03)
}
pub fn store(funct3: u32, rs2: u8, rs1: u8, imm: i32) -> u32 {
    s(imm, rs2, rs1, funct3, 0x23)
}
pub fn branch(funct3: u32, rs1: u8, rs2: u8, imm: i32) -> u32 {
    b(imm, rs2, rs1, funct3)
}

/// `li rd, v` as `lui` + `addi`.
pub fn li(rd: u8, v: u32) -> [u32; 2] {
    let lo = ((v & 0xfff) as i32) << 20 >> 20; // sign-extended low 12 bits
    let hi = v.wrapping_sub(lo as u32) >> 12;
    [lui(rd, hi), addi(rd, rd, lo)]
}
