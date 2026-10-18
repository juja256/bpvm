//! Gadget environment: the constraint system plus all shared lookups and arguments.
//!
//! Gadgets take native witness values as `Option<_>` (`Some` for the prover, `None` for the
//! verifier) and linear combinations for the constrained quantities; both sides run the same
//! code so the circuits match.

use std::sync::Arc;

use bulletproofs::r1cs::{LinearCombination, R1CSError, RandomizableConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;

use crate::logup::{LogUp, Lookup, Table};

pub type Lc = LinearCombination;

pub fn s(x: u64) -> Scalar {
    Scalar::from(x)
}

/// $2^k$ as a scalar, $k \le 127$.
pub fn pow2(k: u32) -> Scalar {
    Scalar::from(1u128 << k)
}

pub fn lc<T: Into<Lc>>(x: T) -> Lc {
    x.into()
}

/// Field element of a signed integer.
pub fn signed(x: i64) -> Scalar {
    if x >= 0 {
        s(x as u64)
    } else {
        -s(x.unsigned_abs())
    }
}

/// Bitwise-op tags in the nibble table.
pub const TAG_XOR: u64 = 0;
pub const TAG_OR: u64 = 1;
pub const TAG_AND: u64 = 2;

/// Range table: rows $(x, k)$ for $k \in [1, 8]$, $x < 2^k$ — one table serves every
/// partial-byte range check.
fn range_table() -> Table {
    let rows = (1..=8u64).flat_map(|k| (0..1u64 << k).map(move |x| vec![s(x), s(k)])).collect();
    Table::new(2, rows)
}

/// Rows $(s, 2^s)$ for $s < 32$.
fn pow_table() -> Table {
    Table::new(2, (0..32u32).map(|i| vec![s(i as u64), s(1u64 << i)]).collect())
}

/// Rows $(\mathsf{tag}, a, b, a \circ b)$ over nibbles for XOR, OR, AND.
fn bitop_table() -> Table {
    let mut rows = Vec::new();
    for (tag, f) in [(TAG_XOR, (|a, b| a ^ b) as fn(u64, u64) -> u64), (TAG_OR, |a, b| a | b), (TAG_AND, |a, b| a & b)] {
        for a in 0..16 {
            for b in 0..16 {
                rows.push(vec![s(tag), s(a), s(b), s(f(a, b))]);
            }
        }
    }
    Table::new(4, rows)
}

/// Width of a memory tuple $(\mathsf{key}, \mathsf{value}, t)$.
pub const MEM_WIDTH: usize = 3;
/// Width of a bus tuple $(\mathsf{op}, \mathsf{clk}, \mathsf{pc}, \mathsf{next\_pc}, \mathsf{imm}, v_1, v_2, v_d)$.
pub const BUS_WIDTH: usize = 8;
/// Bits for timestamp gaps $t - t_{\text{prev}} - 1$.
pub const TS_BITS: u32 = 24;

pub struct Env<'a, CS: RandomizableConstraintSystem> {
    pub cs: &'a mut CS,
    pub range: Lookup,
    pub pow: Lookup,
    pub bitop: Lookup,
    pub fetch: Lookup,
    pub mem: LogUp,
    pub bus: LogUp,
}

impl<'a, CS: RandomizableConstraintSystem> Env<'a, CS> {
    pub fn new(cs: &'a mut CS, program: Table) -> Self {
        Env {
            cs,
            range: Lookup::new(Arc::new(range_table())),
            pow: Lookup::new(Arc::new(pow_table())),
            bitop: Lookup::new(Arc::new(bitop_table())),
            fetch: Lookup::new(Arc::new(program)),
            mem: LogUp::new(MEM_WIDTH),
            bus: LogUp::new(BUS_WIDTH),
        }
    }

    /// Multipliers the arguments will add in phase 2.
    pub fn phase2_multipliers(&self) -> usize {
        self.range.phase2_multipliers()
            + self.pow.phase2_multipliers()
            + self.bitop.phase2_multipliers()
            + self.fetch.phase2_multipliers()
            + self.mem.phase2_multipliers()
            + self.bus.phase2_multipliers()
    }

    /// Commit multiplicities and emit all reciprocal arguments.
    pub fn finish(self) -> Result<(), R1CSError> {
        let Env { cs, range, pow, bitop, fetch, mem, bus } = self;
        range.finalize(cs)?;
        pow.finalize(cs)?;
        bitop.finalize(cs)?;
        fetch.finalize(cs)?;
        mem.finalize(cs)?;
        bus.finalize(cs)
    }

    pub fn alloc(&mut self, v: Option<u64>) -> Result<Variable, R1CSError> {
        self.cs.allocate(v.map(s))
    }

    pub fn alloc_scalar(&mut self, v: Option<Scalar>) -> Result<Variable, R1CSError> {
        self.cs.allocate(v)
    }

    pub fn constrain(&mut self, x: Lc) {
        self.cs.constrain(x);
    }

    /// Product of two linear combinations (one multiplier).
    pub fn mul(&mut self, a: Lc, b: Lc) -> Variable {
        self.cs.multiply(a, b).2
    }

    /// A boolean variable (one multiplier: $b(1-b) = 0$).
    pub fn boolean(&mut self, v: Option<bool>) -> Result<Variable, R1CSError> {
        let (l, r, o) = self.cs.allocate_multiplier(v.map(|b| (s(b as u64), s(!b as u64))))?;
        self.cs.constrain(l + r - Scalar::ONE);
        self.cs.constrain(o.into());
        Ok(l)
    }

    /// Constrain $0 \le x < 2^{bits}$ by little-endian byte digits; returns the digits.
    pub fn range_bits(&mut self, x: Lc, v: Option<u64>, bits: u32) -> Result<Vec<Variable>, R1CSError> {
        assert!((1..=64).contains(&bits));
        let mut acc = x;
        let mut digits = Vec::new();
        let mut done = 0;
        while done < bits {
            let k = (bits - done).min(8);
            let d = self.alloc(v.map(|v| (v >> done) & ((1 << k) - 1)))?;
            self.range.query(vec![d.into(), lc(s(k as u64))]);
            acc = acc - d * pow2(done);
            digits.push(d);
            done += k;
        }
        self.cs.constrain(acc);
        Ok(digits)
    }

    pub fn range32(&mut self, x: Lc, v: Option<u32>) -> Result<Vec<Variable>, R1CSError> {
        self.range_bits(x, v.map(|v| v as u64), 32)
    }

    /// $z = [x = 0]$ (two multipliers).
    pub fn is_zero(&mut self, x: Lc, v: Option<Scalar>) -> Result<Variable, R1CSError> {
        let z = self.alloc_scalar(v.map(|v| s((v == Scalar::ZERO) as u64)))?;
        let inv = self.alloc_scalar(v.map(|v| if v == Scalar::ZERO { Scalar::ZERO } else { v.invert() }))?;
        let p = self.mul(x.clone(), inv.into());
        self.cs.constrain(p + z - Scalar::ONE);
        let q = self.mul(x, z.into());
        self.cs.constrain(q.into());
        Ok(z)
    }

    /// Sign bit of a 32-bit value: $x = \ell + 2^{31}\sigma$, $\ell < 2^{31}$.
    /// Also range-checks $x$ to 32 bits.
    pub fn msb32(&mut self, x: Lc, v: Option<u32>) -> Result<Variable, R1CSError> {
        let sigma = self.boolean(v.map(|v| v >> 31 == 1))?;
        self.range_bits(x - sigma * pow2(31), v.map(|v| (v & 0x7fff_ffff) as u64), 31)?;
        Ok(sigma)
    }

    /// $[a < b]$ for 32-bit $a, b$: $a - b + 2^{32} \cdot lt \in [0, 2^{32})$.
    pub fn ltu(&mut self, a: Lc, b: Lc, va: Option<u32>, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let w = va.zip(vb);
        let lt = self.boolean(w.map(|(a, b)| a < b))?;
        let d = a - b + lt * pow2(32);
        self.range32(d, w.map(|(a, b)| a.wrapping_sub(b)))?;
        Ok(lt)
    }

    /// $[a < b]$ signed: flip sign bits and compare unsigned.
    pub fn lt_signed(&mut self, a: Lc, b: Lc, va: Option<u32>, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let sa = self.msb32(a.clone(), va)?;
        let sb = self.msb32(b.clone(), vb)?;
        let flip = |x: Lc, sx: Variable| x + pow2(31) - sx * pow2(32);
        self.ltu(flip(a, sa), flip(b, sb), va.map(|v| v ^ 0x8000_0000), vb.map(|v| v ^ 0x8000_0000))
    }

    /// Nibble-wise bitwise op: constrains $r = a \circ b$ for 32-bit values.
    pub fn bitop(&mut self, tag: u64, a: Lc, b: Lc, r: Lc, w: Option<(u32, u32, u32)>) -> Result<(), R1CSError> {
        let (mut ea, mut eb, mut er) = (a, b, r);
        for i in 0..8 {
            let nib = |x: u32| ((x >> (4 * i)) & 0xf) as u64;
            let na = self.alloc(w.map(|w| nib(w.0)))?;
            let nb = self.alloc(w.map(|w| nib(w.1)))?;
            let nr = self.alloc(w.map(|w| nib(w.2)))?;
            self.bitop.query(vec![lc(s(tag)), na.into(), nb.into(), nr.into()]);
            let k = pow2(4 * i);
            ea = ea - na * k;
            eb = eb - nb * k;
            er = er - nr * k;
        }
        self.cs.constrain(ea);
        self.cs.constrain(eb);
        self.cs.constrain(er);
        Ok(())
    }

    /// Shift amount $b \bmod 32$ for a 32-bit $b$: returns $p = 2^{b \bmod 32}$.
    pub fn shift_pow(&mut self, b: Lc, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let sh = self.alloc(vb.map(|b| (b & 31) as u64))?;
        let p = self.alloc(vb.map(|b| 1u64 << (b & 31)))?;
        self.pow.query(vec![sh.into(), p.into()]);
        let hi = b - sh;
        // hi = 32 * h with h < 2^27
        let h = self.alloc(vb.map(|b| (b >> 5) as u64))?;
        self.cs.constrain(hi - h * s(32));
        self.range_bits(h.into(), vb.map(|b| (b >> 5) as u64), 27)?;
        Ok(p)
    }
}
