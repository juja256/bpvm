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

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bpvm_emu::{Image, Trace};
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, R1CSProof, RandomizableConstraintSystem, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::chips::{chip, ram_key, MemW, Row};
use crate::gadgets::*;
use crate::isa::{canon, program_table, Fields, Op, ProgRow, PROG_WIDTH};
use crate::logup::Table;

#[derive(Clone, Debug)]
pub struct Statement {
    pub program: Vec<ProgRow>,
    pub entry: u32,
    /// Initial RAM image: (word-aligned address, value). Accesses outside it are unprovable.
    pub ram: Vec<(u32, u32)>,
    pub steps: usize,
    /// Number of executed instructions per opcode (the chip capacities).
    pub op_counts: BTreeMap<Op, usize>,
    pub exit_code: u32,
}

impl Statement {
    /// Absorb the statement into the transcript (strong Fiat–Shamir: the R1CS transcript
    /// does not hash the constraint system itself).
    fn bind(&self, t: &mut Transcript) {
        t.append_message(b"bpvm-version", b"0");
        t.append_u64(b"entry", self.entry as u64);
        t.append_u64(b"steps", self.steps as u64);
        t.append_u64(b"exit", self.exit_code as u64);
        for r in &self.program {
            for x in r.to_scalars() {
                t.append_message(b"prog", x.as_bytes());
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
pub struct Witness {
    cpu: Vec<CpuRow>,
    chips: BTreeMap<Op, Vec<Row>>,
    final_regs: [(u32, u64); 32],
    final_ram: Vec<(u32, u64)>,
}

/// Build the public statement and the witness from an image and its execution trace.
pub fn witness(img: &Image, trace: &Trace) -> Result<(Statement, Witness), String> {
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

    let stmt = Statement {
        program: program_table(img),
        entry: img.entry,
        ram: img.data.iter().map(|(a, v)| (*a, *v)).collect(),
        steps: trace.steps.len(),
        op_counts: chips.iter().map(|(op, rows)| (*op, rows.len())).collect(),
        exit_code: trace.exit_code,
    };
    let final_regs = std::array::from_fn(|r| (regs[r], reg_t[r]));
    let final_ram = ram.values().copied().collect();
    Ok((stmt, Witness { cpu, chips, final_regs, final_ram }))
}

/// Build the circuit; returns the number of phase-2 multipliers.
fn synthesize<CS: RandomizableConstraintSystem>(cs: &mut CS, st: &Statement, wit: Option<&Witness>) -> Result<usize, R1CSError> {
    if st.steps == 0 {
        return Err(R1CSError::GadgetError { description: "empty trace".into() });
    }
    let program = Table::new(PROG_WIDTH, st.program.iter().map(|r| r.to_scalars()).collect());
    let mut env = Env::new(cs, program);

    // CPU chip
    let mut pc: Lc = lc(s(st.entry as u64));
    for k in 0..st.steps {
        let r = wit.map(|w| &w.cpu[k]);
        let f = r.map(|r| r.fields);
        let op = env.alloc(f.map(|f| f.op as u64))?;
        let rd = env.alloc(f.map(|f| f.rd as u64))?;
        let rs1 = env.alloc(f.map(|f| f.rs1 as u64))?;
        let rs2 = env.alloc(f.map(|f| f.rs2 as u64))?;
        let imm = env.alloc(f.map(|f| f.imm as u64))?;
        let wr = env.alloc(f.map(|f| f.wr as u64))?;
        env.fetch.query(vec![pc.clone(), op.into(), rd.into(), rs1.into(), rs2.into(), imm.into(), wr.into()]);

        let v1 = env.alloc(r.map(|r| r.v1 as u64))?;
        let v2 = env.alloc(r.map(|r| r.v2 as u64))?;
        let vd = env.alloc(r.map(|r| r.vd as u64))?;
        let next_pc = env.alloc(r.map(|r| r.next_pc as u64))?;
        let old = env.alloc(r.map(|r| r.old as u64))?;
        let tp: Vec<_> = (0..3).map(|i| env.alloc(r.map(|r| r.t_prev[i]))).collect::<Result<_, _>>()?;

        let delta = env.mul(wr.into(), vd - old);
        let new = old + delta;
        env.range32(vd.into(), r.map(|r| r.vd))?;

        let k64 = k as u64;
        let accesses = [(rs1, lc(v1), lc(v1)), (rs2, lc(v2), lc(v2)), (rd, lc(old), new)];
        for (i, (key, read, write)) in accesses.into_iter().enumerate() {
            let t = 4 * k64 + 1 + i as u64;
            env.range_bits(lc(s(t)) - tp[i] - Scalar::ONE, r.map(|r| t - 1 - r.t_prev[i]), TS_BITS)?;
            env.mem.add(vec![key.into(), read, tp[i].into()]);
            env.mem.sub(vec![key.into(), write, lc(s(t))]);
        }

        env.bus.add(vec![op.into(), lc(s(k64)), pc.clone(), next_pc.into(), imm.into(), v1.into(), v2.into(), vd.into()]);

        if k + 1 == st.steps {
            env.constrain(op - Op::ECALL.id());
            env.constrain(v2 - s(st.exit_code as u64));
        }
        pc = next_pc.into();
    }

    // Opcode chips
    for (op, n) in &st.op_counts {
        for i in 0..*n {
            chip(&mut env, *op, wit.map(|w| &w.chips[op][i]))?;
        }
    }

    // Memory boundary: Init (public, free) and Final (witness).
    for r in 0..32u64 {
        env.mem.add_public(lc(-Scalar::ONE), vec![s(r), Scalar::ZERO, Scalar::ZERO]);
        let fin = wit.map(|w| w.final_regs[r as usize]);
        let v = env.alloc(fin.map(|f| f.0 as u64))?;
        let t = env.alloc(fin.map(|f| f.1))?;
        env.mem.add(vec![lc(s(r)), v.into(), t.into()]);
    }
    for (j, (addr, init)) in st.ram.iter().enumerate() {
        let key = ram_key(*addr);
        env.mem.add_public(lc(-Scalar::ONE), vec![key, s(*init as u64), Scalar::ZERO]);
        let fin = wit.map(|w| w.final_ram[j]);
        let v = env.alloc(fin.map(|f| f.0 as u64))?;
        let t = env.alloc(fin.map(|f| f.1))?;
        env.mem.add(vec![lc(key), v.into(), t.into()]);
    }

    let phase2 = env.phase2_multipliers();
    env.finish()?;
    Ok(phase2)
}

#[derive(Clone, Debug)]
pub struct Stats {
    pub multipliers: usize,
    pub padded: usize,
    pub proof_bytes: usize,
    pub time: Duration,
}

fn gens_for(n: usize) -> BulletproofGens {
    BulletproofGens::new(n.next_power_of_two(), 1)
}

pub fn prove(st: &Statement, wit: &Witness) -> Result<(R1CSProof, Stats), R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"bpvm");
    st.bind(&mut transcript);
    let mut prover = Prover::new(&pc_gens, &mut transcript);
    let phase2 = synthesize(&mut prover, st, Some(wit))?;
    let n = prover.metrics().multipliers + phase2;
    let proof = prover.prove(&gens_for(n))?;
    let stats = Stats { multipliers: n, padded: n.next_power_of_two(), proof_bytes: proof.to_bytes().len(), time: start.elapsed() };
    Ok((proof, stats))
}

pub fn verify(st: &Statement, proof: &R1CSProof) -> Result<Duration, R1CSError> {
    let start = Instant::now();
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"bpvm");
    st.bind(&mut transcript);
    let mut verifier = Verifier::new(&mut transcript);
    let phase2 = synthesize(&mut verifier, st, None)?;
    let n = verifier.metrics().multipliers + phase2;
    verifier.verify(proof, &pc_gens, &gens_for(n))?;
    Ok(start.elapsed())
}
