//! Gadget environment: the constraint system plus all shared tables and arguments.
//!
//! Gadgets take native witness values as `Option<_>` (`Some` for the prover, `None` for the
//! verifier) and linear combinations for the constrained quantities; both sides run the same
//! code so the circuits match. Lookups and reciprocal arguments are the builder operations of
//! the bulletproofs fork ([`CircuitBuilder`]): the same circuit is proven with Bulletproofs
//! (logUp over randomized constraints) or natively with Bulletproofs++ (reciprocal form).

use bulletproofs::curve::Field;
use bulletproofs::r1cs::{CircuitBuilder, LinearCombination, R1CSError, Reciprocal, TableId, Variable};

/// A linear combination over the circuit's field `F` (the scalars of its curve).
pub type Lc<F> = LinearCombination<F>;

pub fn s<F: Field>(x: u64) -> F {
    F::from(x)
}

/// $2^k$ as a scalar, $k \le 127$.
pub fn pow2<F: Field>(k: u32) -> F {
    F::from_u128(1u128 << k)
}

pub fn lc<F: Field, T: Into<Lc<F>>>(x: T) -> Lc<F> {
    x.into()
}

/// Field element of a signed integer.
pub fn signed<F: Field>(x: i64) -> F {
    if x >= 0 {
        s::<F>(x as u64)
    } else {
        -s::<F>(x.unsigned_abs())
    }
}

/// Bitwise-op tags in the nibble table.
pub const TAG_XOR: u64 = 0;
pub const TAG_OR: u64 = 1;
pub const TAG_AND: u64 = 2;

/// Digits of range checks are at most this many bits (one table per width up to it).
pub const DIGIT_BITS: u32 = 8;
// Loads and stores read the digits of `range32` as the four bytes of a word.
const _: () = assert!(DIGIT_BITS == 8);

/// Rows $(s, 2^s)$ for $s < 32$.
fn pow_rows() -> Vec<Vec<u64>> {
    (0..32u32).map(|i| vec![i as u64, 1u64 << i]).collect()
}

/// Rows $(\mathsf{tag}, a, b, a \circ b)$ over nibbles for XOR, OR, AND.
fn bitop_rows() -> Vec<Vec<u64>> {
    let mut rows = Vec::new();
    for (tag, f) in [(TAG_XOR, (|a, b| a ^ b) as fn(u64, u64) -> u64), (TAG_OR, |a, b| a | b), (TAG_AND, |a, b| a & b)] {
        for a in 0..16 {
            for b in 0..16 {
                rows.push(vec![tag, a, b, f(a, b)]);
            }
        }
    }
    rows
}

/// Widths of the little-endian digits of a `bits`-bit range check: [`DIGIT_BITS`] each, the
/// last one shorter.
fn digit_widths(bits: u32) -> impl Iterator<Item = u32> {
    (0..bits).step_by(DIGIT_BITS as usize).map(move |done| (bits - done).min(DIGIT_BITS))
}

/// Width of a memory tuple $(\mathsf{key}, \mathsf{value}, t)$.
pub const MEM_WIDTH: usize = 3;
/// Width of a bus tuple $(\mathsf{op}, \mathsf{clk}, \mathsf{pc}, \mathsf{next\_pc}, \mathsf{imm}, v_1, v_2, v_d)$.
pub const BUS_WIDTH: usize = 8;
/// Bits for timestamp gaps $t - t_{\text{prev}} - 1$ when the trace length is not given.
pub const TS_BITS: u32 = 24;

/// Bits for the timestamp gaps of a trace of `steps` steps: the smallest multiple of
/// [`DIGIT_BITS`] with $4 \cdot \mathsf{steps} \le 2^{\mathsf{bits}}$. Every timestamp is at most
/// $4 \cdot \mathsf{steps}$ (a CPU access at $4k + 1 + i$, a RAM access at $4k + 4$), and the
/// one a read consumes is a real write's, so an honest gap is below $4 \cdot \mathsf{steps}$; a
/// read from the future gives a negative gap, $p - |d|$, never below $2^{\mathsf{bits}}$.
pub fn ts_bits(steps: usize) -> u32 {
    let max = 4 * steps as u64;
    let need = 64 - max.saturating_sub(1).leading_zeros();
    need.max(1).div_ceil(DIGIT_BITS) * DIGIT_BITS
}

/// The constraint system and the shared tables and arguments. Tables without lookups cost
/// nothing; every table's multiplicities are shared by all its lookups.
pub struct Env<'a, F: Field, CS: CircuitBuilder<F>> {
    pub cs: &'a mut CS,
    /// One-column tables $\{0, \dots, 2^k - 1\}$ for $k = 1, \dots, 8$ (index $k - 1$).
    range: Vec<TableId>,
    pow: TableId,
    bitop: TableId,
    fetch: TableId,
    mem: Reciprocal,
    bus: Reciprocal,
    /// Bits of the timestamp gaps ([`ts_bits`] of the trace; [`TS_BITS`] by default).
    pub ts_bits: u32,
    field: core::marker::PhantomData<F>,
}

impl<'a, F: Field, CS: CircuitBuilder<F>> Env<'a, F, CS> {
    /// `program`: the rows of the program table (fetch lookups).
    pub fn new(cs: &'a mut CS, program: Vec<Vec<u64>>) -> Result<Self, R1CSError> {
        let range = (1..=DIGIT_BITS).map(|k| cs.table((0..1u64 << k).map(|x| vec![x]).collect())).collect::<Result<_, _>>()?;
        let pow = cs.table(pow_rows())?;
        let bitop = cs.table(bitop_rows())?;
        let fetch = cs.table(program)?;
        let mem = cs.reciprocal(MEM_WIDTH)?;
        let bus = cs.reciprocal(BUS_WIDTH)?;
        Ok(Env { cs, range, pow, bitop, fetch, mem, bus, ts_bits: TS_BITS, field: core::marker::PhantomData })
    }

    /// Timestamp gaps sized for a trace of `steps` steps ([`ts_bits`]).
    pub fn for_steps(mut self, steps: usize) -> Self {
        self.ts_bits = ts_bits(steps);
        self
    }

    /// Memory argument (`Init + Writes = Reads + Final` as multisets): a read, or a final
    /// value, `+1 / (X + (key, value, t))`.
    pub fn mem_read(&mut self, tuple: &[Lc<F>]) -> Result<(), R1CSError> {
        self.mem.add(self.cs, tuple)
    }

    /// Memory argument: a write, or a private initial value, `-1 / (X + (key, value, t))`.
    pub fn mem_write(&mut self, tuple: &[Lc<F>]) -> Result<(), R1CSError> {
        self.mem.sub(self.cs, tuple)
    }

    /// Memory argument: a public initial value `(key, value, 0)`, `-1 / (X + row)`.
    pub fn mem_init(&mut self, row: &[u64]) -> Result<(), R1CSError> {
        self.mem.add_public(self.cs, (-F::ONE).into(), row)
    }

    /// Bus: the CPU sends a tuple to an opcode chip.
    pub fn bus_send(&mut self, tuple: &[Lc<F>]) -> Result<(), R1CSError> {
        self.bus.add(self.cs, tuple)
    }

    /// Bus: an opcode chip receives a tuple.
    pub fn bus_receive(&mut self, tuple: &[Lc<F>]) -> Result<(), R1CSError> {
        self.bus.sub(self.cs, tuple)
    }

    /// The one-column table $\{0, \dots, 2^k - 1\}$, $1 \le k \le$ [`DIGIT_BITS`] (for tests).
    #[doc(hidden)]
    pub fn range_table(&self, k: u32) -> TableId {
        self.range[k as usize - 1]
    }

    /// Assert that `row` is a row of the program table.
    pub fn fetch(&mut self, row: &[Lc<F>]) -> Result<(), R1CSError> {
        self.cs.lookup(self.fetch, row)
    }

    /// A free witness (BP: half a multiplier; BP++: no gate).
    pub fn witness(&mut self, v: Option<u64>) -> Result<Variable, R1CSError> {
        self.cs.witness(v.map(s))
    }

    /// A free witness that is any field element.
    pub fn witness_scalar(&mut self, v: Option<F>) -> Result<Variable, R1CSError> {
        self.cs.witness(v)
    }

    pub fn constrain(&mut self, x: Lc<F>) {
        self.cs.constrain(x);
    }

    /// Product of two linear combinations (one multiplier).
    pub fn mul(&mut self, a: Lc<F>, b: Lc<F>) -> Variable {
        self.cs.multiply(a, b).2
    }

    /// A boolean variable (one multiplier: $b(1-b) = 0$).
    pub fn boolean(&mut self, v: Option<bool>) -> Result<Variable, R1CSError> {
        let (l, r, o) = self.cs.allocate_multiplier(v.map(|b| (s::<F>(b as u64), s::<F>(!b as u64))))?;
        self.cs.constrain(lc(l) + r - F::ONE);
        self.cs.constrain(o.into());
        Ok(l)
    }

    /// Constrain $0 \le x < 2^{bits}$ by little-endian byte digits; returns the digits.
    pub fn range_bits(&mut self, x: Lc<F>, v: Option<u64>, bits: u32) -> Result<Vec<Variable>, R1CSError> {
        let digits = v.map(|v| digit_widths(bits).scan(0, |done, k| {
            let d = (v >> *done) & ((1 << k) - 1);
            *done += k;
            Some(d)
        }).collect());
        self.range_digits(x, digits, bits)
    }

    /// [`range_bits`](Self::range_bits) with the prover's digits given (for tests: digits
    /// outside their tables).
    #[doc(hidden)]
    pub fn range_digits(&mut self, x: Lc<F>, digits: Option<Vec<u64>>, bits: u32) -> Result<Vec<Variable>, R1CSError> {
        assert!((1..=64).contains(&bits));
        let mut acc = x;
        let mut vars = Vec::new();
        let mut done = 0;
        for (i, k) in digit_widths(bits).enumerate() {
            let d = self.cs.lookup_value(self.range[k as usize - 1], digits.as_ref().map(|d| d[i]))?;
            acc = acc - d * pow2::<F>(done);
            vars.push(d);
            done += k;
        }
        self.cs.constrain(acc);
        Ok(vars)
    }

    pub fn range32(&mut self, x: Lc<F>, v: Option<u32>) -> Result<Vec<Variable>, R1CSError> {
        self.range_bits(x, v.map(|v| v as u64), 32)
    }

    /// $z = [x = 0]$ (two multipliers).
    pub fn is_zero(&mut self, x: Lc<F>, v: Option<F>) -> Result<Variable, R1CSError> {
        let z = self.witness_scalar(v.map(|v| s::<F>((v == F::ZERO) as u64)))?;
        let inv = self.witness_scalar(v.map(|v| if v == F::ZERO { F::ZERO } else { Option::from(v.invert()).expect("nonzero") }))?;
        let p = self.mul(x.clone(), inv.into());
        self.cs.constrain(lc(p) + z - F::ONE);
        let q = self.mul(x, z.into());
        self.cs.constrain(q.into());
        Ok(z)
    }

    /// Sign bit of a 32-bit value: $x = \ell + 2^{31}\sigma$, $\ell < 2^{31}$.
    /// Also range-checks $x$ to 32 bits.
    pub fn msb32(&mut self, x: Lc<F>, v: Option<u32>) -> Result<Variable, R1CSError> {
        let sigma = self.boolean(v.map(|v| v >> 31 == 1))?;
        self.range_bits(x - sigma * pow2::<F>(31), v.map(|v| (v & 0x7fff_ffff) as u64), 31)?;
        Ok(sigma)
    }

    /// $[a < b]$ for 32-bit $a, b$: $a - b + 2^{32} \cdot lt \in [0, 2^{32})$.
    pub fn ltu(&mut self, a: Lc<F>, b: Lc<F>, va: Option<u32>, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let w = va.zip(vb);
        let lt = self.boolean(w.map(|(a, b)| a < b))?;
        let d = a - b + lt * pow2::<F>(32);
        self.range32(d, w.map(|(a, b)| a.wrapping_sub(b)))?;
        Ok(lt)
    }

    /// $[a < b]$ signed: flip sign bits and compare unsigned.
    pub fn lt_signed(&mut self, a: Lc<F>, b: Lc<F>, va: Option<u32>, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let sa = self.msb32(a.clone(), va)?;
        let sb = self.msb32(b.clone(), vb)?;
        let flip = |x: Lc<F>, sx: Variable| x + pow2::<F>(31) - sx * pow2::<F>(32);
        self.ltu(flip(a, sa), flip(b, sb), va.map(|v| v ^ 0x8000_0000), vb.map(|v| v ^ 0x8000_0000))
    }

    /// Nibble-wise bitwise op: constrains $r = a \circ b$ for 32-bit values.
    pub fn bitop(&mut self, tag: u64, a: Lc<F>, b: Lc<F>, r: Lc<F>, w: Option<(u32, u32, u32)>) -> Result<(), R1CSError> {
        let (mut ea, mut eb, mut er) = (a, b, r);
        for i in 0..8 {
            let nib = |x: u32| ((x >> (4 * i)) & 0xf) as u64;
            let na = self.witness(w.map(|w| nib(w.0)))?;
            let nb = self.witness(w.map(|w| nib(w.1)))?;
            let nr = self.witness(w.map(|w| nib(w.2)))?;
            self.cs.lookup(self.bitop, &[lc(s::<F>(tag)), na.into(), nb.into(), nr.into()])?;
            let k = pow2::<F>(4 * i);
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
    pub fn shift_pow(&mut self, b: Lc<F>, vb: Option<u32>) -> Result<Variable, R1CSError> {
        let sh = self.witness(vb.map(|b| (b & 31) as u64))?;
        let p = self.witness(vb.map(|b| 1u64 << (b & 31)))?;
        self.cs.lookup(self.pow, &[sh.into(), p.into()])?;
        let hi = b - sh;
        // hi = 32 * h with h < 2^27
        let h = self.witness(vb.map(|b| (b >> 5) as u64))?;
        self.cs.constrain(hi - h * s::<F>(32));
        self.range_bits(h.into(), vb.map(|b| (b >> 5) as u64), 27)?;
        Ok(p)
    }
}
