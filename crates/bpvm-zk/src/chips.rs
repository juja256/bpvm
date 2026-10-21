//! Opcode chips: one row per executed instruction of a given opcode.
//!
//! A row receives the bus tuple $(\mathsf{op}, \mathsf{clk}, \mathsf{pc}, \mathsf{next\_pc},
//! \mathsf{imm}, v_1, v_2, v_d)$ that the CPU chip sent, with `op` a constant, and constrains
//! the opcode semantics on it. All register values are 32-bit by invariant: the CPU chip
//! range-checks every `vd`, so every value in the register file and RAM is a 32-bit word.
//! RAM accesses (loads/stores) happen here, at timestamp $4\,\mathsf{clk} + 4$.

use bulletproofs::r1cs::{CircuitBuilder, R1CSError, Variable};
use bulletproofs::curve::Field;

use crate::gadgets::*;
use crate::isa::Op;

/// Native witness of one chip row.
#[derive(Clone, Debug)]
pub struct Row {
    pub op: Op,
    pub clk: u64,
    pub pc: u32,
    pub next_pc: u32,
    pub imm: u32,
    pub v1: u32,
    pub v2: u32,
    pub vd: u32,
    pub mem: Option<MemW>,
}

/// Native witness of a RAM access.
#[derive(Clone, Debug)]
pub struct MemW {
    /// Word-aligned byte address.
    pub addr: u32,
    pub before: u32,
    pub after: u32,
    pub t_prev: u64,
}

/// Memory key of a RAM word (registers use keys 0..31).
pub fn ram_key(word_addr: u32) -> u64 {
    (1 << 32) + (word_addr >> 2) as u64
}

struct Vars {
    clk: Variable,
    pc: Variable,
    next_pc: Variable,
    imm: Variable,
    v1: Variable,
    v2: Variable,
    vd: Variable,
}

pub fn chip<F: Field, CS: CircuitBuilder<F>>(env: &mut Env<'_, F, CS>, op: Op, w: Option<&Row>) -> Result<(), R1CSError> {
    let x = Vars {
        clk: env.witness(w.map(|r| r.clk))?,
        pc: env.witness(w.map(|r| r.pc as u64))?,
        next_pc: env.witness(w.map(|r| r.next_pc as u64))?,
        imm: env.witness(w.map(|r| r.imm as u64))?,
        v1: env.witness(w.map(|r| r.v1 as u64))?,
        v2: env.witness(w.map(|r| r.v2 as u64))?,
        vd: env.witness(w.map(|r| r.vd as u64))?,
    };
    env.bus_receive(&[
        lc(op.id::<F>()),
        x.clk.into(),
        x.pc.into(),
        x.next_pc.into(),
        x.imm.into(),
        x.v1.into(),
        x.v2.into(),
        x.vd.into(),
    ])?;

    use Op::*;
    let imm_form = matches!(op, ADDI | SLTI | SLTIU | XORI | ORI | ANDI | SLLI | SRLI | SRAI);
    // Second ALU operand: rs2 or the immediate.
    let (b, wb): (Variable, Option<u32>) =
        if imm_form { (x.imm, w.map(|r| r.imm)) } else { (x.v2, w.map(|r| r.v2)) };
    let wa = w.map(|r| r.v1);
    let wab = wa.zip(wb);
    let a: Lc<F> = x.v1.into();
    let bl: Lc<F> = b.into();
    let vd: Lc<F> = x.vd.into();
    let t32 = pow2::<F>(32);

    // Sequential control flow unless the opcode says otherwise.
    if !matches!(op, JAL | JALR | BEQ | BNE | BLT | BGE | BLTU | BGEU | ECALL) {
        env.constrain(lc(x.next_pc) - x.pc - s::<F>(4));
    }

    match op {
        LUI => env.constrain(vd - x.imm),
        AUIPC => {
            let c = env.boolean(w.map(|r| (r.pc as u64 + r.imm as u64) >> 32 == 1))?;
            env.constrain(vd - x.pc - x.imm + c * t32);
        }
        JAL => {
            env.constrain(vd - x.pc - s::<F>(4));
            let c = env.boolean(w.map(|r| (r.pc as u64 + r.imm as u64) >> 32 == 1))?;
            env.constrain(lc(x.next_pc) - x.pc - x.imm + c * t32);
        }
        JALR => {
            env.constrain(vd - x.pc - s::<F>(4));
            let sum = w.map(|r| r.v1 as u64 + r.imm as u64);
            let bit = env.boolean(sum.map(|v| v & 1 == 1))?;
            let c = env.boolean(sum.map(|v| v >> 32 == 1))?;
            // next_pc is a fetched (4-aligned) pc, which pins bit and c uniquely.
            env.constrain(a + x.imm - x.next_pc - bit - c * t32);
        }
        BEQ | BNE | BLT | BGE | BLTU | BGEU => {
            let w2 = wa.zip(w.map(|r| r.v2));
            let b2: Lc<F> = x.v2.into();
            let cond: Lc<F> = match op {
                BEQ | BNE => {
                    let z = env.is_zero(a.clone() - b2, w2.map(|(a, b)| s::<F>(a as u64) - s::<F>(b as u64)))?;
                    if op == BEQ { z.into() } else { lc(F::ONE) - z }
                }
                BLTU | BGEU => {
                    let lt = env.ltu(a.clone(), b2, wa, w.map(|r| r.v2))?;
                    if op == BLTU { lt.into() } else { lc(F::ONE) - lt }
                }
                _ => {
                    let lt = env.lt_signed(a.clone(), b2, wa, w.map(|r| r.v2))?;
                    if op == BLT { lt.into() } else { lc(F::ONE) - lt }
                }
            };
            let taken = w.map(|r| {
                let (a, b) = (r.v1, r.v2);
                match op {
                    BEQ => a == b,
                    BNE => a != b,
                    BLT => (a as i32) < (b as i32),
                    BGE => (a as i32) >= (b as i32),
                    BLTU => a < b,
                    _ => a >= b,
                }
            });
            let off = env.mul(cond, x.imm - s::<F>(4));
            let carry = env.boolean(w.zip(taken).map(|(r, t)| {
                (r.pc as u64 + if t { r.imm as u64 } else { 4 }) >> 32 == 1
            }))?;
            env.constrain(lc(x.next_pc) - x.pc - s::<F>(4) - off + carry * t32);
        }

        LB | LH | LW | LBU | LHU | SB | SH | SW => mem_op(env, op, &x, w)?,

        ADD | ADDI => {
            let c = env.boolean(wab.map(|(a, b)| (a as u64 + b as u64) >> 32 == 1))?;
            env.constrain(vd - a - bl + c * t32);
        }
        SUB => {
            let c = env.boolean(wab.map(|(a, b)| a < b))?;
            env.constrain(vd - a + bl - c * t32);
        }
        SLT | SLTI => {
            let lt = env.lt_signed(a, bl, wa, wb)?;
            env.constrain(vd - lt);
        }
        SLTU | SLTIU => {
            let lt = env.ltu(a, bl, wa, wb)?;
            env.constrain(vd - lt);
        }
        XOR | XORI | OR | ORI | AND | ANDI => {
            let tag = match op {
                XOR | XORI => TAG_XOR,
                OR | ORI => TAG_OR,
                _ => TAG_AND,
            };
            env.bitop(tag, a, bl, vd, w.zip(wab).map(|(r, (a, b))| (a, b, r.vd)))?;
        }
        SLL | SLLI => {
            let p = env.shift_pow(bl, wb)?;
            let prod = env.mul(a, p.into());
            let hi = wab.map(|(a, b)| (((a as u64) << (b & 31)) >> 32) as u32);
            let h = env.witness(hi.map(|v| v as u64))?;
            env.constrain(prod - vd - h * t32);
            env.range32(h.into(), hi)?;
        }
        SRL | SRLI | SRA | SRAI => {
            let p = env.shift_pow(bl.clone(), wb)?;
            let sh = wb.map(|b| b & 31);
            let rem_v = wab.map(|(a, b)| a & ((1u64 << (b & 31)) - 1) as u32);
            let rem = env.witness(rem_v.map(|v| v as u64))?;
            env.range32(rem.into(), rem_v)?;
            // rem < p
            env.range32(lc(p) - rem - F::ONE, rem_v.zip(sh).map(|(r, s)| ((1u64 << s) - 1 - r as u64) as u32))?;
            if matches!(op, SRL | SRLI) {
                let qp = env.mul(vd.clone(), p.into());
                env.constrain(a - qp - rem);
            } else {
                let sa = env.msb32(a.clone(), wa)?;
                let u = env.witness(wab.map(|(a, b)| (a >> (b & 31)) as u64))?;
                let up = env.mul(u.into(), p.into());
                env.constrain(a - up - rem);
                // q = 2^(32 - sh), the sign-extension mask is 2^32 - q
                let q = env.witness(sh.map(|s| 1u64 << (32 - s)))?;
                let qp = env.mul(q.into(), p.into());
                env.constrain(qp - t32);
                let m = env.mul(sa.into(), lc(t32) - q);
                env.constrain(vd - u - m);
            }
        }

        MUL | MULHU => {
            let prod = env.mul(a, bl);
            let full = wab.map(|(a, b)| a as u64 * b as u64);
            if op == MUL {
                let hi = full.map(|p| (p >> 32) as u32);
                let h = env.witness(hi.map(|v| v as u64))?;
                env.constrain(prod - vd - h * t32);
                env.range32(h.into(), hi)?;
            } else {
                let lo = full.map(|p| p as u32);
                let l = env.witness(lo.map(|v| v as u64))?;
                env.constrain(lc(prod) - l - vd * t32);
                env.range32(l.into(), lo)?;
            }
        }
        MULH | MULHSU => {
            let sa = env.msb32(a.clone(), wa)?;
            let sa_lc = a - sa * t32;
            let (b_lc, pv) = if op == MULH {
                let sb = env.msb32(bl.clone(), wb)?;
                (bl - sb * t32, wab.map(|(a, b)| a as i32 as i128 * b as i32 as i128))
            } else {
                (bl, wab.map(|(a, b)| a as i32 as i128 * b as i128))
            };
            let prod = env.mul(sa_lc, b_lc);
            let k = env.boolean(pv.map(|p| p < 0))?;
            let lo = pv.map(|p| p as u64 as u32);
            let l = env.witness(lo.map(|v| v as u64))?;
            // P + 2^64 k = lo + 2^32 vd
            env.constrain(prod + k * pow2::<F>(64) - l - vd * t32);
            env.range32(l.into(), lo)?;
        }
        DIVU | REMU => {
            let qr = wab.map(|(a, b)| if b == 0 { (u32::MAX, a) } else { (a / b, a % b) });
            let (q, r): (Lc<F>, Lc<F>) = if op == DIVU {
                let r = env.witness(qr.map(|v| v.1 as u64))?;
                env.range32(r.into(), qr.map(|v| v.1))?;
                (vd.clone(), r.into())
            } else {
                let q = env.witness(qr.map(|v| v.0 as u64))?;
                env.range32(q.into(), qr.map(|v| v.0))?;
                (q.into(), vd.clone())
            };
            let qb = env.mul(q.clone(), bl.clone());
            env.constrain(a - qb - r.clone());
            let zb = env.is_zero(bl.clone(), wb.map(|b| s::<F>(b as u64)))?;
            // b != 0  =>  r < b
            let d = env.mul(lc(F::ONE) - zb, bl - r - F::ONE);
            env.range32(d.into(), wab.zip(qr).map(|((_, b), (_, r))| if b == 0 { 0 } else { b - r - 1 }))?;
            // b == 0  =>  q = 2^32 - 1
            let m = env.mul(zb.into(), q - s::<F>(u32::MAX as u64));
            env.constrain(m.into());
        }
        DIV | REM => {
            let qr = wab.map(|(a, b)| {
                (bpvm_emu::cpu::alu(bpvm_emu::AluOp::Div, a, b), bpvm_emu::cpu::alu(bpvm_emu::AluOp::Rem, a, b))
            });
            let (q, r): (Lc<F>, Lc<F>) = if op == DIV {
                let r = env.witness(qr.map(|v| v.1 as u64))?;
                (vd.clone(), r.into())
            } else {
                let q = env.witness(qr.map(|v| v.0 as u64))?;
                (q.into(), vd.clone())
            };
            let sa = env.msb32(a.clone(), wa)?;
            let sb = env.msb32(bl.clone(), wb)?;
            let sq = env.msb32(q.clone(), qr.map(|v| v.0))?;
            let sr = env.msb32(r.clone(), qr.map(|v| v.1))?;
            let sgn = |x: Lc<F>, sx: Variable| x - sx * t32;
            let (sa_lc, sb_lc, sq_lc, sr_lc) =
                (sgn(a.clone(), sa), sgn(bl.clone(), sb), sgn(q.clone(), sq), sgn(r.clone(), sr));

            // overflow case: a = -2^31, b = -1
            let z1 = env.is_zero(a.clone() - pow2::<F>(31), wa.map(|a| s::<F>(a as u64) - pow2::<F>(31)))?;
            let z2 = env.is_zero(bl.clone() - s::<F>(u32::MAX as u64), wb.map(|b| s::<F>(b as u64) - s::<F>(u32::MAX as u64)))?;
            let ovf = env.mul(z1.into(), z2.into());

            // A = Q B + R  (minus 2^32 in the overflow case)
            let qb = env.mul(sq_lc, sb_lc.clone());
            env.constrain(sa_lc - sr_lc.clone() - qb + ovf * t32);

            // b != 0  =>  |R| < |B|
            let abs_r = env.mul(sr_lc, lc(F::ONE) - sr * s::<F>(2));
            let abs_b = env.mul(sb_lc, lc(F::ONE) - sb * s::<F>(2));
            let zb = env.is_zero(bl.clone(), wb.map(|b| s::<F>(b as u64)))?;
            let d = env.mul(lc(F::ONE) - zb, lc(abs_b) - abs_r - F::ONE);
            let dv = wab.zip(qr).map(|((_, b), (_, r))| {
                if b == 0 {
                    0
                } else {
                    ((b as i32 as i64).abs() - (r as i32 as i64).abs() - 1) as u32
                }
            });
            env.range32(d.into(), dv)?;
            // R != 0  =>  sign(R) = sign(A)
            let m = env.mul(lc(sr) - sa, r);
            env.constrain(m.into());
            // b == 0  =>  q = 2^32 - 1
            let m = env.mul(zb.into(), q - s::<F>(u32::MAX as u64));
            env.constrain(m.into());
        }

        FENCE => {}
        ECALL => {
            env.constrain(a - s::<F>(bpvm_emu::SYSCALL_HALT as u64));
            env.constrain(lc(x.next_pc) - x.pc);
        }
    }
    Ok(())
}

/// Loads and stores: effective address, the RAM word access, byte/half selection.
fn mem_op<F: Field, CS: CircuitBuilder<F>>(env: &mut Env<'_, F, CS>, op: Op, x: &Vars, w: Option<&Row>) -> Result<(), R1CSError> {
    use Op::*;
    let t32 = pow2::<F>(32);
    let ea = w.map(|r| r.v1 as u64 + r.imm as u64);
    let addr = ea.map(|e| e as u32);
    let c = env.boolean(ea.map(|e| e >> 32 == 1))?;
    let widx = env.witness(addr.map(|a| (a >> 2) as u64))?;
    env.range_bits(widx.into(), addr.map(|a| (a >> 2) as u64), 30)?;
    let addr_lc = lc(x.v1) + x.imm - c * t32;

    // Offset within the word as one-hot selectors (alignment enforced per width).
    let off = addr.map(|a| a & 3);
    let sel: [Lc<F>; 4] = match op {
        LW | SW => {
            env.constrain(addr_lc - widx * s::<F>(4));
            [lc(F::ONE), lc(F::ZERO), lc(F::ZERO), lc(F::ZERO)]
        }
        LH | LHU | SH => {
            let s2 = env.boolean(off.map(|o| o == 2))?;
            env.constrain(addr_lc - widx * s::<F>(4) - s2 * s::<F>(2));
            [lc(F::ONE) - s2, lc(F::ZERO), s2.into(), lc(F::ZERO)]
        }
        _ => {
            let b: Vec<Variable> = (0..4).map(|i| env.boolean(off.map(|o| o == i))).collect::<Result<_, _>>()?;
            env.constrain(lc(b[0]) + b[1] + b[2] + b[3] - F::ONE);
            env.constrain(addr_lc - widx * s::<F>(4) - b[1] - b[2] * s::<F>(2) - b[3] * s::<F>(3));
            [b[0].into(), b[1].into(), b[2].into(), b[3].into()]
        }
    };

    // RAM access at t = 4 clk + 4.
    let m = w.and_then(|r| r.mem.as_ref());
    let key = lc(widx) + pow2::<F>(32);
    let t = x.clk * s::<F>(4) + s::<F>(4);
    let tp = env.witness(m.map(|m| m.t_prev))?;
    env.range_bits(t.clone() - tp - F::ONE, w.zip(m).map(|(r, m)| 4 * r.clk + 3 - m.t_prev), TS_BITS)?;
    let wb_v = m.map(|m| m.before);

    let (before, after): (Lc<F>, Lc<F>) = match op {
        LW => (x.vd.into(), x.vd.into()),
        LB | LBU | LH | LHU => {
            let wv = env.witness(wb_v.map(|v| v as u64))?;
            let bytes = env.range32(wv.into(), wb_v)?;
            let (val, bits): (Lc<F>, u32) = if matches!(op, LB | LBU) {
                let mut byte = lc(F::ZERO);
                for i in 0..4 {
                    byte = byte + env.mul(sel[i].clone(), bytes[i].into());
                }
                (byte, 8)
            } else {
                let h0 = bytes[0] + bytes[1] * s::<F>(256);
                let h1 = bytes[2] + bytes[3] * s::<F>(256);
                let d = env.mul(sel[2].clone(), h1 - h0.clone());
                (h0 + d, 16)
            };
            let raw = wb_v.zip(off).map(|(w, o)| (w >> (8 * o)) & ((1u64 << bits) - 1) as u32);
            if matches!(op, LBU | LHU) {
                env.constrain(lc(x.vd) - val);
            } else {
                let sg = env.boolean(raw.map(|r| r >> (bits - 1) == 1))?;
                env.range_bits(val.clone() - sg * pow2::<F>(bits - 1), raw.map(|r| (r & ((1 << (bits - 1)) - 1)) as u64), bits - 1)?;
                env.constrain(lc(x.vd) - val - sg * (t32 - pow2::<F>(bits)));
            }
            (wv.into(), wv.into())
        }
        SW => {
            let wv = env.witness(wb_v.map(|v| v as u64))?;
            (wv.into(), x.v2.into())
        }
        _ => {
            // SB / SH: replace a byte / half of the old word with the low bits of v2.
            let bits = if op == SB { 8 } else { 16 };
            let wv = env.witness(wb_v.map(|v| v as u64))?;
            let bytes = env.range32(wv.into(), wb_v)?;
            let v2 = w.map(|r| r.v2);
            let nv = v2.map(|v| (v & ((1u64 << bits) - 1) as u32) as u64);
            let n = env.witness(nv)?;
            let rest = env.witness(v2.map(|v| (v >> bits) as u64))?;
            env.range_bits(n.into(), nv, bits)?;
            env.range_bits(rest.into(), v2.map(|v| (v >> bits) as u64), 32 - bits)?;
            env.constrain(lc(x.v2) - n - rest * pow2::<F>(bits));
            let mut after = lc(wv);
            if op == SB {
                for i in 0..4 {
                    let d = env.mul(sel[i].clone(), lc(n) - bytes[i]);
                    after = after + d * pow2::<F>(8 * i as u32);
                }
            } else {
                let h0 = bytes[0] + bytes[1] * s::<F>(256);
                let h1 = bytes[2] + bytes[3] * s::<F>(256);
                let low = lc(n) - h0;
                let d = env.mul(sel[2].clone(), (lc(n) - h1) * pow2::<F>(16) - low.clone());
                after = after + low + d;
            }
            (wv.into(), after)
        }
    };
    env.mem_read(&[key.clone(), before, tp.into()])?;
    env.mem_write(&[key, after, t])?;
    Ok(())
}
