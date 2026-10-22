//! The whole VM circuit: CPU chip, opcode chips, memory boundary; prove and verify.
//!
//! **Statement** (public): program table, entry point, initial RAM image, number of steps,
//! per-opcode instruction counts (chip capacities) and the exit code. **Claim**: running the
//! program from the entry point with zeroed registers and that RAM image executes exactly
//! `steps` instructions and halts via `ecall` with `a0 = exit_code`.
//!
//! CPU row $k$ (timestamps $4k+1, 4k+2, 4k+3$ for rs1, rs2, rd):
//! - fetch: $(\mathsf{pc}_k, \mathsf{op}, rd, rs_1, rs_2, \mathsf{imm}, \mathsf{wr})$ is a row of
//!   the program table; $\mathsf{pc}_0 = \mathsf{entry}$, $\mathsf{pc}_{k+1} = \mathsf{next\_pc}_k$;
//! - registers: read $rs_1, rs_2$, read the old value of $rd$ and write
//!   $\mathsf{old} + \mathsf{wr}\cdot(v_d - \mathsf{old})$; every access is a read tuple
//!   $(\mathsf{key}, v, t_{\text{prev}})$ and a write tuple $(\mathsf{key}, v', t)$ with
//!   $t_{\text{prev}} < t$;
//! - $v_d$ is range-checked to 32 bits;
//! - the bus tuple goes to the chip of `op`, which checks the semantics.
//!
//! Memory consistency: $\mathsf{Init} \uplus \mathsf{Writes} = \mathsf{Reads} \uplus \mathsf{Final}$
//! over registers (keys 0..31) and RAM words (keys $2^{32} + \mathsf{addr}/4$).
//!
//! **I/O.** Public inputs are simply part of the RAM image. A private input is a group of
//! RAM words whose $\mathsf{Init}$ values are witnesses $w_k$ (range-checked to 32 bits)
//! with $\sum_k 2^{32k} w_k = v$, where $v$ is opened by a Pedersen commitment
//! $V = vB + r\tilde B$ given in the statement. Outputs constrain $\mathsf{Final}$ values:
//! to public constants, or to a committed $v$ in the same way (no range check needed:
//! final values are 32-bit by the memory invariant).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bpvm_emu::{Image, Trace};
use bulletproofs::r1cs::{Backend, ConstraintSystem, Cost, Prover, R1CSError, R1CSProof, Variable, Verifier};
use bulletproofs::curve::ff::Field as _;
use bulletproofs::curve::{Curve, Field};
use bulletproofs::{BulletproofGens, PedersenGens, Sha256Transcript, TranscriptBackend};
use merlin::Transcript;

use crate::chips::{chip, ram_key, MemW, Row};
use crate::gadgets::*;
use crate::isa::{canon, program_table, Fields, Op, ProgRow};

/// The statement over the curve `C` (ristretto255 by default).
#[derive(Clone, Debug)]
pub struct Statement<C: Curve> {
    pub program: Vec<ProgRow>,
    pub entry: u32,
    /// Initial RAM image: (word-aligned address, value). Accesses outside it are unprovable.
    pub ram: Vec<(u32, u32)>,
    pub steps: usize,
    /// Number of executed instructions per opcode (the chip capacities).
    pub op_counts: BTreeMap<Op, usize>,
    pub exit_code: u32,
    /// Committed inputs: their RAM words (zero in `ram`) and Pedersen commitments.
    pub private_in: Vec<Committed<C>>,
    /// Committed outputs: final values of these words open the commitments.
    pub private_out: Vec<Committed<C>>,
    /// Revealed outputs: (word address, final value).
    pub public_out: Vec<(u32, u32)>,
}

/// A value $v = \sum_k 2^{32k}\,\mathsf{mem}[\mathsf{words}_k]$ bound by a Pedersen commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed<C: Curve> {
    pub words: Vec<u32>,
    pub commitment: C::Compressed,
}

/// Prover-side I/O choices: which word groups are committed (with blindings) and which
/// words are revealed.
#[derive(Clone, Debug, Default)]
pub struct IoSpec<F: Field> {
    pub private_in: Vec<(Vec<u32>, F)>,
    pub private_out: Vec<(Vec<u32>, F)>,
    pub public_out: Vec<u32>,
}

/// Value of a little-endian word group (at most two words).
fn join(words: impl IntoIterator<Item = u32>) -> u64 {
    words.into_iter().enumerate().fold(0, |acc, (k, w)| {
        assert!(k < 2, "committed values are at most 64 bits");
        acc | (w as u64) << (32 * k)
    })
}

impl<C: Curve> Statement<C> {
    /// The statement for running `img` (public inputs already patched in): private input
    /// words are zeroed in the public RAM image.
    pub fn new(
        img: &Image,
        steps: usize,
        op_counts: BTreeMap<Op, usize>,
        exit_code: u32,
        private_in: Vec<Committed<C>>,
        private_out: Vec<Committed<C>>,
        public_out: Vec<(u32, u32)>,
    ) -> Statement<C> {
        let hidden: std::collections::BTreeSet<u32> = private_in.iter().flat_map(|c| c.words.iter().copied()).collect();
        let ram = img.data.iter().map(|(a, v)| (*a, if hidden.contains(a) { 0 } else { *v })).collect();
        Statement { program: program_table(img), entry: img.entry, ram, steps, op_counts, exit_code, private_in, private_out, public_out }
    }

    /// Absorb the statement into the transcript (strong Fiat–Shamir: the R1CS transcript
    /// does not hash the constraint system itself).
    pub(crate) fn bind<T: TranscriptBackend + ?Sized>(&self, t: &mut T) {
        t.append_message(b"bpvm-version", b"1");
        t.append_u64(b"entry", self.entry as u64);
        t.append_u64(b"steps", self.steps as u64);
        t.append_u64(b"exit", self.exit_code as u64);
        for r in &self.program {
            for x in r.to_scalars::<C::Scalar>() {
                t.append_message(b"prog", &x.to_bytes32());
            }
        }
        for (a, v) in &self.ram {
            t.append_u64(b"ram-addr", *a as u64);
            t.append_u64(b"ram-val", *v as u64);
        }
        for (op, n) in &self.op_counts {
            t.append_u64(b"op", *op as u64);
            t.append_u64(b"count", *n as u64);
        }
        // Commitments themselves are absorbed by `Prover::commit` / `Verifier::commit`.
        for (label, group) in [(b"in" as &[u8], &self.private_in), (b"out", &self.private_out)] {
            t.append_u64(label, group.len() as u64);
            for c in group {
                t.append_u64(b"words", c.words.len() as u64);
                for a in &c.words {
                    t.append_u64(b"addr", *a as u64);
                }
            }
        }
        for (a, v) in &self.public_out {
            t.append_u64(b"pub-out-addr", *a as u64);
            t.append_u64(b"pub-out-val", *v as u64);
        }
    }
}

#[derive(Clone, Debug)]
struct CpuRow {
    fields: Fields,
    next_pc: u32,
    v1: u32,
    v2: u32,
    vd: u32,
    old: u32,
    t_prev: [u64; 3],
}

#[derive(Clone, Debug)]
/// The witness over the field `F` (the scalars of the statement's curve).
pub struct Witness<F: Field> {
    cpu: Vec<CpuRow>,
    chips: BTreeMap<Op, Vec<Row>>,
    final_regs: [(u32, u64); 32],
    final_ram: Vec<(u32, u64)>,
    /// Initial values of all RAM words (the public image has private inputs zeroed).
    init_ram: BTreeMap<u32, u32>,
    /// (value, blinding) of each private input, then of each private output.
    openings: Vec<(u64, F)>,
}

impl<F: Field> Witness<F> {
    /// (value, blinding) of each private input, then of each private output.
    pub fn openings(&self) -> &[(u64, F)] {
        &self.openings
    }
}

/// Build the public statement and the witness over the curve `C` from an image and its
/// execution trace.
pub fn witness<C: Curve>(img: &Image, trace: &Trace) -> Result<(Statement<C>, Witness<C::Scalar>), String> {
    witness_with_io::<C>(img, trace, &IoSpec::default())
}

/// As [`witness`], with committed inputs/outputs and revealed outputs.
pub fn witness_with_io<C: Curve>(img: &Image, trace: &Trace, io: &IoSpec<C::Scalar>) -> Result<(Statement<C>, Witness<C::Scalar>), String> {
    let mut regs = [0u32; 32];
    let mut reg_t = [0u64; 32];
    let mut ram: BTreeMap<u32, (u32, u64)> = img.data.iter().map(|(a, v)| (*a, (*v, 0))).collect();

    let mut cpu = Vec::with_capacity(trace.steps.len());
    let mut chips: BTreeMap<Op, Vec<Row>> = BTreeMap::new();

    for (k, st) in trace.steps.iter().enumerate() {
        let k64 = k as u64;
        let f = canon(st.instr).ok_or_else(|| format!("unsupported instruction at pc {:#x}", st.pc))?;
        let mut access = |r: u8, t: u64| {
            let tp = reg_t[r as usize];
            reg_t[r as usize] = t;
            tp
        };
        let v1 = regs[f.rs1 as usize];
        let tp1 = access(f.rs1, 4 * k64 + 1);
        let v2 = regs[f.rs2 as usize];
        let tp2 = access(f.rs2, 4 * k64 + 2);
        let old = regs[f.rd as usize];
        let tp3 = access(f.rd, 4 * k64 + 3);
        let vd = st.result;
        if f.wr {
            regs[f.rd as usize] = vd;
        }

        let mem = match st.mem {
            None => None,
            Some(m) => {
                let e = ram.get_mut(&m.addr).ok_or_else(|| {
                    format!("access to {:#x} at pc {:#x} is outside the RAM image", m.addr, st.pc)
                })?;
                assert_eq!(e.0, m.before, "emulator/witness RAM mismatch");
                let t_prev = e.1;
                *e = (m.after, 4 * k64 + 4);
                Some(MemW { addr: m.addr, before: m.before, after: m.after, t_prev })
            }
        };

        cpu.push(CpuRow { fields: f, next_pc: st.next_pc, v1, v2, vd, old, t_prev: [tp1, tp2, tp3] });
        chips.entry(f.op).or_default().push(Row {
            op: f.op,
            clk: k64,
            pc: st.pc,
            next_pc: st.next_pc,
            imm: f.imm,
            v1,
            v2,
            vd,
            mem,
        });
    }

    let pc_gens = PedersenGens::<C>::default();
    let word = |m: &BTreeMap<u32, u32>, a: &u32| m.get(a).copied().ok_or_else(|| format!("I/O word {a:#x} is outside the RAM image"));
    let final_mem: BTreeMap<u32, u32> = ram.iter().map(|(a, (v, _))| (*a, *v)).collect();
    let mut openings = Vec::new();
    let mut commit = |mem: &BTreeMap<u32, u32>, groups: &[(Vec<u32>, C::Scalar)]| -> Result<Vec<Committed<C>>, String> {
        groups
            .iter()
            .map(|(words, r)| {
                let v = join(words.iter().map(|a| word(mem, a)).collect::<Result<Vec<_>, _>>()?);
                openings.push((v, *r));
                Ok(Committed { words: words.clone(), commitment: C::compress(&pc_gens.commit(C::Scalar::from(v), *r)) })
            })
            .collect()
    };
    let private_in = commit(&img.data, &io.private_in)?;
    let private_out = commit(&final_mem, &io.private_out)?;
    let public_out = io.public_out.iter().map(|a| Ok((*a, word(&final_mem, a)?))).collect::<Result<_, String>>()?;

    let op_counts = chips.iter().map(|(op, rows)| (*op, rows.len())).collect();
    let stmt = Statement::new(img, trace.steps.len(), op_counts, trace.exit_code, private_in, private_out, public_out);
    let final_regs = std::array::from_fn(|r| (regs[r], reg_t[r]));
    let final_ram = ram.values().copied().collect();
    Ok((stmt, Witness { cpu, chips, final_regs, final_ram, init_ram: img.data.clone(), openings }))
}

/// Build the circuit. `committed`: variables of the statement's commitments, inputs then
/// outputs.
fn synthesize<C: Curve, CS: ConstraintSystem<C::Scalar>>(cs: &mut CS, st: &Statement<C>, wit: Option<&Witness<C::Scalar>>, committed: &[Variable]) -> Result<(), R1CSError> {
    if st.steps == 0 {
        return Err(R1CSError::GadgetError { description: "empty trace".into() });
    }
    let mut env = Env::new(cs, st.program.iter().map(|r| r.to_row()).collect())?.for_steps(st.steps);

    // CPU chip
    let mut pc: Lc<C::Scalar> = lc(s::<C::Scalar>(st.entry as u64));
    for k in 0..st.steps {
        let r = wit.map(|w| &w.cpu[k]);
        let f = r.map(|r| r.fields);
        let op = env.witness(f.map(|f| f.op as u64))?;
        let rd = env.witness(f.map(|f| f.rd as u64))?;
        let rs1 = env.witness(f.map(|f| f.rs1 as u64))?;
        let rs2 = env.witness(f.map(|f| f.rs2 as u64))?;
        let imm = env.witness(f.map(|f| f.imm as u64))?;
        let wr = env.witness(f.map(|f| f.wr as u64))?;
        env.fetch(&[pc.clone(), op.into(), rd.into(), rs1.into(), rs2.into(), imm.into(), wr.into()])?;

        let v1 = env.witness(r.map(|r| r.v1 as u64))?;
        let v2 = env.witness(r.map(|r| r.v2 as u64))?;
        let vd = env.witness(r.map(|r| r.vd as u64))?;
        let next_pc = env.witness(r.map(|r| r.next_pc as u64))?;
        let old = env.witness(r.map(|r| r.old as u64))?;
        let tp: Vec<_> = (0..3).map(|i| env.witness(r.map(|r| r.t_prev[i]))).collect::<Result<_, _>>()?;

        let delta = env.mul(lc(wr), lc(vd) - old)?;
        let new = lc(old) + delta;
        env.range32(vd.into(), r.map(|r| r.vd))?;

        let k64 = k as u64;
        let accesses = [(rs1, lc(v1), lc(v1)), (rs2, lc(v2), lc(v2)), (rd, lc(old), new)];
        for (i, (key, read, write)) in accesses.into_iter().enumerate() {
            let t = 4 * k64 + 1 + i as u64;
            env.range_bits(lc(s::<C::Scalar>(t)) - tp[i] - C::Scalar::ONE, r.map(|r| t - 1 - r.t_prev[i]), env.ts_bits)?;
            env.mem_read(&[key.into(), read, tp[i].into()])?;
            env.mem_write(&[key.into(), write, lc(s::<C::Scalar>(t))])?;
        }

        env.bus_send(&[op.into(), lc(s::<C::Scalar>(k64)), pc.clone(), next_pc.into(), imm.into(), v1.into(), v2.into(), vd.into()])?;

        if k + 1 == st.steps {
            env.constrain(lc(op) - Op::ECALL.id::<C::Scalar>());
            env.constrain(v2 - s::<C::Scalar>(st.exit_code as u64));
        }
        pc = next_pc.into();
    }

    // Opcode chips
    for (op, n) in &st.op_counts {
        for i in 0..*n {
            chip(&mut env, *op, wit.map(|w| &w.chips[op][i]))?;
        }
    }

    // Memory boundary: Init (public, free) and Final (witness). Only the registers the program
    // names: an access takes its register from the fetched row of the public program table, so
    // no other register is ever accessed, and the init and final read of one would cancel.
    let named: std::collections::BTreeSet<u64> = st.program.iter().flat_map(|r| [r.fields.rd, r.fields.rs1, r.fields.rs2]).map(|x| x as u64).collect();
    for r in named {
        env.mem_init(&[r, 0, 0])?;
        let fin = wit.map(|w| w.final_regs[r as usize]);
        let v = env.witness(fin.map(|f| f.0 as u64))?;
        let t = env.witness(fin.map(|f| f.1))?;
        env.mem_read(&[lc(s::<C::Scalar>(r)), v.into(), t.into()])?;
    }
    let (cin, cout) = committed.split_at(st.private_in.len());
    // word address -> (index of the committed value, limb index)
    let limbs = |group: &[Committed<C>]| -> BTreeMap<u32, (usize, usize)> {
        group.iter().enumerate().flat_map(|(i, c)| c.words.iter().enumerate().map(move |(k, a)| (*a, (i, k)))).collect()
    };
    let (in_limbs, out_limbs) = (limbs(&st.private_in), limbs(&st.private_out));
    let public_out: BTreeMap<u32, u32> = st.public_out.iter().copied().collect();
    let mut in_sum: Vec<Lc<C::Scalar>> = cin.iter().map(|v| lc(*v)).collect();
    let mut out_sum: Vec<Lc<C::Scalar>> = cout.iter().map(|v| lc(*v)).collect();

    for (j, (addr, init)) in st.ram.iter().enumerate() {
        let key = ram_key(*addr);
        match in_limbs.get(addr) {
            None => env.mem_init(&[key, *init as u64, 0])?,
            Some(&(i, k)) => {
                let w = wit.map(|w| w.init_ram[addr]);
                let v = env.witness(w.map(u64::from))?;
                env.range32(v.into(), w)?;
                in_sum[i] = in_sum[i].clone() - v * pow2::<C::Scalar>(32 * k as u32);
                env.mem_write(&[lc(key), v.into(), lc(C::Scalar::ZERO)])?;
            }
        }
        let fin = wit.map(|w| w.final_ram[j]);
        let v = env.witness(fin.map(|f| f.0 as u64))?;
        let t = env.witness(fin.map(|f| f.1))?;
        env.mem_read(&[lc(key), v.into(), t.into()])?;
        if let Some(&(i, k)) = out_limbs.get(addr) {
            out_sum[i] = out_sum[i].clone() - v * pow2::<C::Scalar>(32 * k as u32);
        }
        if let Some(x) = public_out.get(addr) {
            env.constrain(v - s::<C::Scalar>(*x as u64));
        }
    }
    let covered = |m: &BTreeMap<u32, (usize, usize)>| m.keys().all(|a| st.ram.binary_search_by_key(a, |(b, _)| *b).is_ok());
    if !covered(&in_limbs) || !covered(&out_limbs) || !public_out.keys().all(|a| st.ram.binary_search_by_key(a, |(b, _)| *b).is_ok()) {
        return Err(R1CSError::GadgetError { description: "I/O word outside the RAM image".into() });
    }
    for x in in_sum.into_iter().chain(out_sum) {
        env.constrain(x);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Stats {
    pub backend: Backend,
    /// BP: multipliers; BP++: gates ($N_p + N_m$).
    pub gates: usize,
    /// BP++: the length of the linear part of the commitments ($N_{lin}$: free witnesses,
    /// multiplicities, copies); BP: 0.
    pub linear: usize,
    /// The `BulletproofGens` capacity the proof needs (BP: the multipliers rounded up to a power
    /// of two).
    pub gens_capacity: usize,
    pub proof_bytes: usize,
    pub time: Duration,
}

impl Stats {
    fn new(backend: Backend, cost: &Cost) -> Stats {
        let (gates, linear, gens_capacity) = (cost.gates(backend), cost.linear(backend), cost.gens_capacity(backend));
        Stats { backend, gates, linear, gens_capacity, proof_bytes: 0, time: Duration::ZERO }
    }
}

/// Generators of capacity at least `n`, shared across proofs and verifications in this process
/// (deriving them is a hash-to-group per point). The cache only grows: it keeps
/// 320 bytes per generator pair for the largest circuit seen so far.
fn gens<C: Curve>(n: usize) -> std::sync::Arc<BulletproofGens<C>> {
    // one cache per curve, grown on demand
    use std::any::{Any, TypeId};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static GENS: OnceLock<Mutex<HashMap<TypeId, Box<dyn Any + Send + Sync>>>> = OnceLock::new();
    let need = n.next_power_of_two();
    let mut map = GENS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    let entry = map.entry(TypeId::of::<C>()).or_insert_with(|| Box::new(Arc::new(BulletproofGens::<C>::new(1, 1))));
    let gens = entry.downcast_mut::<Arc<BulletproofGens<C>>>().expect("the cache holds this curve's generators");
    if gens.gens_capacity < need {
        let mut g = (**gens).clone();
        g.increase_capacity(need);
        *gens = Arc::new(g);
    }
    gens.clone()
}

fn commit_prover<C: Curve, T: TranscriptBackend>(prover: &mut Prover<'_, &mut T, C>, st: &Statement<C>, wit: &Witness<C::Scalar>) -> Result<Vec<Variable>, R1CSError> {
    let expected = st.private_in.iter().chain(&st.private_out);
    if wit.openings.len() != st.private_in.len() + st.private_out.len() {
        return Err(R1CSError::GadgetError { description: "openings do not match the statement".into() });
    }
    expected
        .zip(&wit.openings)
        .map(|(c, (v, r))| {
            let (point, var) = prover.commit(C::Scalar::from(*v), *r);
            if point != c.commitment {
                return Err(R1CSError::GadgetError { description: "opening does not match the commitment".into() });
            }
            Ok(var)
        })
        .collect()
}

/// The cost of the circuit for `st` on both backends (synthesized without a witness).
pub fn cost<C: Curve>(st: &Statement<C>) -> Result<Cost, R1CSError> {
    let mut transcript = Transcript::new(b"bpvm-size");
    let mut verifier = Verifier::<_, C>::new(&mut transcript);
    let committed: Vec<Variable> =
        st.private_in.iter().chain(&st.private_out).map(|c| verifier.commit(c.commitment)).collect();
    synthesize(&mut verifier, st, None, &committed)?;
    Ok(verifier.cost())
}

/// The Fiat–Shamir transcript of a proof. Not part of the proof's encoding: the verifier must
/// use the prover's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TranscriptKind {
    /// Merlin (STROBE over Keccak), the default.
    #[default]
    Merlin,
    /// SHA-256 only (`bulletproofs::Sha256Transcript`), for verifiers without Keccak such as
    /// Simplicity on Liquid.
    Sha256,
}

impl TranscriptKind {
    pub fn name(self) -> &'static str {
        match self {
            TranscriptKind::Merlin => "merlin",
            TranscriptKind::Sha256 => "sha256",
        }
    }
}

impl std::str::FromStr for TranscriptKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "merlin" => Ok(TranscriptKind::Merlin),
            "sha256" => Ok(TranscriptKind::Sha256),
            _ => Err("expected merlin or sha256".into()),
        }
    }
}

/// Prove under Merlin ([`prove_with`] picks the transcript).
pub fn prove<C: Curve>(st: &Statement<C>, wit: &Witness<C::Scalar>, backend: Backend) -> Result<(R1CSProof<C>, Stats), R1CSError> {
    prove_staged(st, wit, backend, |_| {})
}

/// [`prove`] under the transcript `kind`.
pub fn prove_with<C: Curve>(st: &Statement<C>, wit: &Witness<C::Scalar>, backend: Backend, kind: TranscriptKind) -> Result<(R1CSProof<C>, Stats), R1CSError> {
    match kind {
        TranscriptKind::Merlin => prove_in(Transcript::new(b"bpvm"), st, wit, backend, |_| {}),
        TranscriptKind::Sha256 => prove_in(Sha256Transcript::new(b"bpvm"), st, wit, backend, |_| {}),
    }
}

/// [`prove`] with a callback after each stage ("synthesized"), for profiling.
#[doc(hidden)]
pub fn prove_staged<C: Curve>(st: &Statement<C>, wit: &Witness<C::Scalar>, backend: Backend, stage: impl FnMut(&'static str)) -> Result<(R1CSProof<C>, Stats), R1CSError> {
    prove_in(Transcript::new(b"bpvm"), st, wit, backend, stage)
}

fn prove_in<C: Curve, T: TranscriptBackend>(mut transcript: T, st: &Statement<C>, wit: &Witness<C::Scalar>, backend: Backend, mut stage: impl FnMut(&'static str)) -> Result<(R1CSProof<C>, Stats), R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens::<C>::default();
    st.bind(&mut transcript);
    let mut prover = Prover::new(&pc_gens, &mut transcript);
    prover.set_backend(backend);
    let committed = commit_prover(&mut prover, st, wit)?;
    synthesize(&mut prover, st, Some(wit), &committed)?;
    stage("synthesized");
    let mut stats = Stats::new(backend, &prover.cost());
    let proof = prover.prove(&gens::<C>(stats.gens_capacity))?;
    stats.proof_bytes = proof.to_bytes().len();
    stats.time = start.elapsed();
    Ok((proof, stats))
}

/// Verify with the backend that produced `proof` (each backend is a sound proof system on
/// its own; the encoding names it), under Merlin ([`verify_with`] picks the transcript).
pub fn verify<C: Curve>(st: &Statement<C>, proof: &R1CSProof<C>) -> Result<Duration, R1CSError> {
    verify_with(st, proof, TranscriptKind::Merlin)
}

/// [`verify`] under the transcript `kind` (the prover's).
pub fn verify_with<C: Curve>(st: &Statement<C>, proof: &R1CSProof<C>, kind: TranscriptKind) -> Result<Duration, R1CSError> {
    match kind {
        TranscriptKind::Merlin => verify_in(Transcript::new(b"bpvm"), st, proof),
        TranscriptKind::Sha256 => verify_in(Sha256Transcript::new(b"bpvm"), st, proof),
    }
}

fn verify_in<C: Curve, T: TranscriptBackend>(mut transcript: T, st: &Statement<C>, proof: &R1CSProof<C>) -> Result<Duration, R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens::<C>::default();
    st.bind(&mut transcript);
    let mut verifier = Verifier::<_, C>::new(&mut transcript);
    verifier.set_backend(proof.backend());
    let committed: Vec<Variable> =
        st.private_in.iter().chain(&st.private_out).map(|c| verifier.commit(c.commitment)).collect();
    synthesize(&mut verifier, st, None, &committed)?;
    let cap = verifier.cost().gens_capacity(proof.backend());
    verifier.verify(proof, &pc_gens, &gens::<C>(cap))?;
    Ok(start.elapsed())
}

/// Proofs a Simplicity verifier on Liquid checks (feature `simplicity`): BP++ over secp256k1
/// with the SHA-256 transcript, bound to the spending transaction's `sig_all_hash`.
#[cfg(feature = "simplicity")]
pub mod simplicity {
    use super::*;
    use bulletproofs::curve::Secp256k1;
    use bulletproofs::simplicity::{CompileTranscript, SimplicityVerifier, SIGHASH_LABEL};

    /// Prove `st` for the transaction whose `sig_all_hash` is `sighash`.
    pub fn prove(st: &Statement<Secp256k1>, wit: &Witness<<Secp256k1 as Curve>::Scalar>, sighash: &[u8; 32]) -> Result<(R1CSProof<Secp256k1>, Stats), R1CSError> {
        // the sighash first: prove_in binds the statement
        let mut t = Sha256Transcript::new(b"bpvm");
        t.append_message(SIGHASH_LABEL, sighash);
        prove_in(t, st, wit, Backend::Bppp, |_| {})
    }

    /// The Simplicity program that verifies [`prove`]'s proofs of `st`.
    pub fn compile(st: &Statement<Secp256k1>) -> Result<SimplicityVerifier, R1CSError> {
        let mut t = CompileTranscript::new(b"bpvm");
        t.append_message(SIGHASH_LABEL, &[0u8; 32]);
        st.bind(&mut t);
        let pc_gens = PedersenGens::<Secp256k1>::default();
        let mut verifier = Verifier::<_, Secp256k1>::new(&mut t);
        verifier.set_backend(Backend::Bppp);
        let committed: Vec<Variable> =
            st.private_in.iter().chain(&st.private_out).map(|c| verifier.commit(c.commitment)).collect();
        synthesize(&mut verifier, st, None, &committed)?;
        let cap = verifier.cost().gens_capacity(Backend::Bppp);
        verifier.compile_to_simplicity(&pc_gens, &gens::<Secp256k1>(cap))
    }
}
