//! The command line: prove and verify with both backends, and proof files the verifier must
//! refuse before (or instead of) running the verifier.

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
