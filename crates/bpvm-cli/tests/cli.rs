//! The command line: prove and verify with both backends and both curves, and proof files the
//! verifier must refuse before (or instead of) running the verifier.

use std::path::PathBuf;
use std::process::Command;

fn bpvm(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bpvm")).args(args).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

fn fib() -> Option<String> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/fib/fib.elf");
    std::path::Path::new(p).exists().then(|| p.to_string()).or_else(|| {
        eprintln!("skipping: build guest/fib/fib.elf with `make -C guest`");
        None
    })
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bpvm-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

/// Write `f(proof file)` next to the original and verify it.
fn verify_edited(elf: &str, proof: &PathBuf, name: &str, f: impl Fn(&mut serde_json::Value), extra: &[&str]) -> (bool, String) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(proof).unwrap()).unwrap();
    f(&mut v);
    let p = tmp(name);
    std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    let mut args = vec!["verify", elf, p.to_str().unwrap()];
    args.extend_from_slice(extra);
    bpvm(&args)
}

#[test]
fn prove_and_verify_with_both_backends() {
    let Some(elf) = fib() else { return };
    for (b, other) in [("bp", "bppp"), ("bppp", "bp")] {
        let (proof, sec) = (tmp(&format!("{b}.proof.json")), tmp(&format!("{b}.secrets.json")));
        let (ok, out) = bpvm(&["prove", &elf, "--backend", b, "-o", proof.to_str().unwrap(), "-s", sec.to_str().unwrap()]);
        assert!(ok, "{out}");
        let (ok, out) = bpvm(&["verify", &elf, proof.to_str().unwrap()]);
        assert!(ok && out.contains(&format!("{b})")), "{out}");
        let (ok, out) = bpvm(&["verify", &elf, proof.to_str().unwrap(), "--backend", b]);
        assert!(ok, "{out}");
        let (ok, out) = bpvm(&["verify", &elf, proof.to_str().unwrap(), "--backend", other]);
        assert!(!ok && out.contains("was required"), "{out}");

        let reject = |name: &str, f: &dyn Fn(&mut serde_json::Value), msg: &str| {
            let (ok, out) = verify_edited(&elf, &proof, &format!("{b}.{name}.json"), f, &[]);
            assert!(!ok && out.contains(msg), "{b} {name}: {out}");
        };
        reject("backend", &|v| v["backend"] = other.into(), "the file says backend");
        reject("no-backend", &|v| drop(v.as_object_mut().unwrap().remove("backend")), "missing \"backend\"");
        reject("version", &|v| v["bpvm"] = 1.into(), "proof file version 1");
        reject("steps", &|v| v["steps"] = 50_000_000u64.into(), "steps must be in");
        reject("zero-steps", &|v| v["steps"] = 0.into(), "steps must be in");
        reject("op-counts", &|v| v["steps"] = (v["steps"].as_u64().unwrap() + 1).into(), "do not add up");
        reject("exit", &|v| v["exit_code"] = 54.into(), "verifier rejected");
    }
}

/// `--transcript sha256`: the proof file records the transcript and `verify` follows it; the
/// same proof under another transcript name is rejected.
#[test]
fn prove_and_verify_under_sha256() {
    let Some(elf) = fib() else { return };
    for b in ["bp", "bppp"] {
        let (proof, sec) = (tmp(&format!("fib-sha-{b}.proof.json")), tmp(&format!("fib-sha-{b}.secrets.json")));
        let (ok, out) = bpvm(&["prove", &elf, "--backend", b, "--transcript", "sha256", "-o", proof.to_str().unwrap(), "-s", sec.to_str().unwrap()]);
        assert!(ok, "{out}");
        assert!(out.contains("(sha256)"), "{out}");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&proof).unwrap()).unwrap();
        assert_eq!(v["transcript"], "sha256");
        let (ok, out) = bpvm(&["verify", &elf, proof.to_str().unwrap()]);
        assert!(ok && out.contains("sha256"), "{out}");
        let (ok, _) = verify_edited(&elf, &proof, &format!("fib-sha-{b}-as-merlin.json"), |v| v["transcript"] = "merlin".into(), &[]);
        assert!(!ok, "{b}: a SHA-256 proof verified as merlin");
        let (ok, _) = verify_edited(&elf, &proof, &format!("fib-sha-{b}-unnamed.json"), |v| { v.as_object_mut().unwrap().remove("transcript"); }, &[]);
        assert!(!ok, "{b}: a SHA-256 proof verified with no transcript named (merlin)");
        let (ok, out) = verify_edited(&elf, &proof, &format!("fib-sha-{b}-bad.json"), |v| v["transcript"] = "keccak".into(), &[]);
        assert!(!ok && out.contains("transcript"), "{out}");
    }
    let (ok, out) = bpvm(&["--transcript", "sha256", &elf]);
    assert!(ok && out.contains("sanity"), "{out}");
}

fn mul() -> (String, String) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../guest/mul/");
    (format!("{dir}mul.elf"), format!("{dir}mul.json"))
}

/// Prove `guest/mul` to files under `name`, with `extra` flags; the proof file.
fn prove_mul(name: &str, extra: &[&str]) -> (PathBuf, serde_json::Value) {
    let (elf, input) = mul();
    let (proof, sec) = (tmp(&format!("{name}.proof.json")), tmp(&format!("{name}.secrets.json")));
    let mut args = vec!["prove", &elf, "-i", &input, "-o", proof.to_str().unwrap(), "-s", sec.to_str().unwrap()];
    args.extend_from_slice(extra);
    let (ok, out) = bpvm(&args);
    assert!(ok, "{out}");
    let v = serde_json::from_slice(&std::fs::read(&proof).unwrap()).unwrap();
    (proof, v)
}

/// `--curve secp256k1`: the proof file records the curve (33-byte SEC1 commitments), and
/// `verify` follows it.
#[test]
fn secp256k1_proof_file_round_trip() {
    let (elf, _) = mul();
    let (proof, v) = prove_mul("mul-secp", &["--curve", "secp256k1", "--backend", "bppp", "--transcript", "sha256"]);
    assert_eq!(v["curve"], "secp256k1");
    assert_eq!(v["private_inputs"]["a"][0].as_str().unwrap().len(), 66);
    let (ok, out) = bpvm(&["verify", &elf, proof.to_str().unwrap()]);
    assert!(ok && out.contains("secp256k1") && out.contains("c = 7000310003"), "{out}");
}

/// ristretto255 is the default, and a proof file that names no curve is read as ristretto255.
#[test]
fn ristretto_is_the_default_and_a_file_without_curve_verifies() {
    let (elf, _) = mul();
    let (proof, v) = prove_mul("mul-ristretto", &[]);
    assert_eq!(v["curve"], "ristretto255");
    let (ok, out) = verify_edited(&elf, &proof, "mul-ristretto-unnamed.json", |v| drop(v.as_object_mut().unwrap().remove("curve")), &[]);
    assert!(ok, "{out}");
}

/// A secp256k1 proof file relabelled as ristretto255 (or an unknown curve) is refused.
#[test]
fn a_proof_under_another_curve_is_rejected() {
    let (elf, _) = mul();
    let (proof, _) = prove_mul("mul-swap", &["--curve", "secp256k1"]);
    let (ok, out) = verify_edited(&elf, &proof, "mul-swap-ristretto.json", |v| v["curve"] = "ristretto255".into(), &[]);
    assert!(!ok, "{out}");
    let (ok, out) = verify_edited(&elf, &proof, "mul-swap-p256.json", |v| v["curve"] = "p256".into(), &[]);
    assert!(!ok && out.contains("p256"), "{out}");
}

#[test]
fn unknown_curve_is_an_error() {
    let (elf, input) = mul();
    let (ok, out) = bpvm(&["run", &elf, "-i", &input, "--curve", "p256"]);
    assert!(!ok && out.contains("p256"), "{out}");
}

#[test]
fn demo_runs_on_secp256k1() {
    let (elf, input) = mul();
    let (ok, out) = bpvm(&["--curve", "secp256k1", &elf, "-i", &input]);
    assert!(ok && out.contains("on secp256k1") && out.contains("sanity"), "{out}");
}

/// `run` reports the stack the run touched against the size the guest was linked with.
#[test]
fn run_reports_the_stack() {
    let (elf, input) = mul();
    let (ok, out) = bpvm(&["run", &elf, "-i", &input]);
    assert!(ok && out.contains("stack:    0 of 16 bytes touched"), "{out}");
}
