//! Multipliers per opcode, per CPU row and fixed, measured on the circuit itself:
//! cost(op) = (size(capacity n+K) − size(n)) / K, so one-off table costs are excluded
//! (averaged: two single `allocate`s share one multiplier, so rows can cost half-integers).
//! `cargo run --release -p bpvm-zk --example op_costs [guest.elf ...]`

use bpvm_emu::{Image, Machine};
use bpvm_zk::isa::Op;
use bpvm_zk::{multipliers, witness, Statement};

fn load(path: &str) -> Statement {
    let img = Image::from_elf(&std::fs::read(path).expect(path)).unwrap();
    let trace = Machine::from_image(&img).run(1 << 22).unwrap();
    witness(&img, &trace).unwrap().0
}

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
    let base = load(&format!("{dir}guest/fib/fib.elf"));
    let size = |f: &dyn Fn(&mut Statement)| {
        let mut st = base.clone();
        f(&mut st);
        multipliers(&st).unwrap()
    };

    const K: usize = 16;
    let per = |f: &dyn Fn(&mut Statement, usize)| {
        (size(&|s| f(s, K + 1)) - size(&|s| f(s, 1))) as f64 / K as f64
    };
    let cpu = per(&|s, k| s.steps += k);
    let cost = |op: Op| per(&|s, k| *s.op_counts.entry(op).or_default() += k);
    let costs: Vec<(Op, f64)> = Op::ALL.iter().map(|&op| (op, cost(op))).collect();

    println!("CPU row (every instruction): {cpu}\n");
    println!("| opcode | chip | total per instruction |\n|---|---|---|");
    for (op, c) in &costs {
        println!("| {op:?} | {c} | {} |", c + cpu);
    }

    // Check the model against real programs: fixed + steps·cpu + Σ count·cost.
    let mut paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        paths = vec![format!("{dir}guest/fib/fib.elf"), format!("{dir}guest/sha256/sha256.elf")];
    }
    println!();
    for p in paths {
        let st = load(&p);
        let actual = multipliers(&st).unwrap();
        let variable = st.steps as f64 * cpu + st.op_counts.iter().map(|(op, n)| *n as f64 * costs[*op as usize].1).sum::<f64>();
        println!(
            "{p}: {} steps, {actual} multipliers = {variable:.0} per-instruction ({:.1}/step) + {:.0} fixed (tables, registers, RAM boundary)",
            st.steps,
            variable / st.steps as f64,
            actual as f64 - variable
        );
    }
}
