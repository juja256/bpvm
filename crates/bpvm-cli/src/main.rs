//! `bpvm <program.elf>` — execute, prove, verify.

use std::process::ExitCode;

use bpvm_emu::{Image, Machine};

const MAX_STEPS: u64 = 1 << 20;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: bpvm <program.elf>");
        return ExitCode::FAILURE;
    };
    match run(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let img = Image::from_elf(&bytes)?;
    println!(
        "loaded {path}: entry {:#x}, {} code words, {} RAM words",
        img.entry,
        img.code.len(),
        img.data.len()
    );

    let trace = Machine::from_image(&img).run(MAX_STEPS).map_err(|t| format!("execution trapped: {t:?}"))?;
    println!("executed {} steps, exit code {}", trace.steps.len(), trace.exit_code);

    let (stmt, wit) = bpvm_zk::witness(&img, &trace)?;
    let mix: Vec<String> = stmt.op_counts.iter().map(|(op, n)| format!("{op:?}×{n}")).collect();
    println!("instruction mix: {}", mix.join(" "));

    let (proof, stats) = bpvm_zk::prove(&stmt, &wit).map_err(|e| format!("prover: {e:?}"))?;
    println!(
        "proved:   {} multipliers (padded to {}), proof {} bytes, {:.2?}",
        stats.multipliers, stats.padded, stats.proof_bytes, stats.time
    );

    let t = bpvm_zk::verify(&stmt, &proof).map_err(|e| format!("verifier rejected: {e:?}"))?;
    println!("verified: program halts with exit code {} after {} steps ({t:.2?})", stmt.exit_code, stmt.steps);

    let mut forged = stmt.clone();
    forged.exit_code ^= 1;
    match bpvm_zk::verify(&forged, &proof) {
        Err(_) => println!("sanity:   the same proof is rejected for exit code {}", forged.exit_code),
        Ok(_) => return Err("proof verified against a forged exit code".into()),
    }
    Ok(())
}
