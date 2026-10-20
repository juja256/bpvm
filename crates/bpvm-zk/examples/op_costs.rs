//! Cost per opcode, per CPU row and fixed, measured on the circuit itself:
//! cost(op) = (size(capacity n+K) − size(n)) / K, so one-off table costs are excluded.
//! Three measures: BP multipliers (two single witnesses share one multiplier, so rows can
//! cost half-integers), BP++ gates ($N_p + N_m$) and BP++ linear slots ($N_{lin}$: the free
//! witnesses, multiplicities and copies that do not fit into the gates' spare output slots;
//! they cost no gate but lengthen the commitments). $N_{lin}$ is net of the gates, so an
//! opcode's linear delta can be negative and the additive model holds only once
//! $N_{lin} > 0$.
//! `cargo run --release -p bpvm-zk --example op_costs [guest.elf ...]`

use bpvm_emu::{Image, Machine};
use bpvm_zk::isa::Op;
use bpvm_zk::{cost, witness, Statement};
use bulletproofs::r1cs::Cost;

fn load(path: &str) -> Statement {
    let img = Image::from_elf(&std::fs::read(path).expect(path)).unwrap();
    let trace = Machine::from_image(&img).run(1 << 22).unwrap();
    witness(&img, &trace).unwrap().0
}

/// (BP multipliers, BP++ gates, BP++ linear slots).
fn measures(c: &Cost) -> [f64; 3] {
    [(c.bp_phase1 + c.bp_phase2) as f64, c.bppp_gates as f64, c.bppp_linear as f64]
}

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
    let base = load(&format!("{dir}guest/fib/fib.elf"));
    let size = |f: &dyn Fn(&mut Statement)| {
        let mut st = base.clone();
        f(&mut st);
        measures(&cost(&st).unwrap())
    };

    const K: usize = 16;
    let per = |f: &dyn Fn(&mut Statement, usize)| {
        let (a, b) = (size(&|s| f(s, K + 1)), size(&|s| f(s, 1)));
        [0, 1, 2].map(|i| (a[i] - b[i]) / K as f64)
    };
    let cpu = per(&|s, k| s.steps += k);
    let op_cost = |op: Op| per(&|s, k| *s.op_counts.entry(op).or_default() += k);
    let costs: Vec<(Op, [f64; 3])> = Op::ALL.iter().map(|&op| (op, op_cost(op))).collect();

    println!("CPU row (every instruction): BP {} multipliers; BP++ {} gates, {} linear\n", cpu[0], cpu[1], cpu[2]);
    println!("| opcode | BP chip | BP total | BP++ chip gates | BP++ total gates | BP++ total linear |\n|---|---|---|---|---|---|");
    for (op, c) in &costs {
        println!("| {op:?} | {} | {} | {} | {} | {} |", c[0], c[0] + cpu[0], c[1], c[1] + cpu[1], c[2] + cpu[2]);
    }

    // Check the model against real programs: fixed + steps·cpu + Σ count·cost.
    let mut paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        paths = vec![format!("{dir}guest/fib/fib.elf"), format!("{dir}guest/sha256/sha256.elf")];
    }
    println!();
    for p in paths {
        let st = load(&p);
        let actual = measures(&cost(&st).unwrap());
        for (i, name) in ["BP multipliers", "BP++ gates", "BP++ linear"].iter().enumerate() {
            let variable = st.steps as f64 * cpu[i] + st.op_counts.iter().map(|(op, n)| *n as f64 * costs[*op as usize].1[i]).sum::<f64>();
            println!(
                "{p}: {} steps, {:.0} {name} = {variable:.0} per-instruction ({:.1}/step) + {:.0} fixed (tables, registers, RAM boundary)",
                st.steps,
                actual[i],
                variable / st.steps as f64,
                actual[i] - variable
            );
        }
    }
}
