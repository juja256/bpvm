//! bpvm command line.
//!
//! ```text
//! bpvm run    <elf> [-i input.json]                                   execute only
//! bpvm prove  <elf> [-i input.json] [-o proof.json] [-s secrets.json] [--backend bp|bppp]
//!             [--transcript merlin|sha256] [--curve ristretto255|secp256k1]   execute and prove
//! bpvm verify <elf> <proof.json> [--backend bp|bppp]                verify
//! bpvm [--no-prove] [--backend bp|bppp] [--transcript merlin|sha256] [--curve ..] <elf> [-i input.json]
//!                                               demo: prove, verify, reject a forged exit code
//! ```
//!
//! `--curve` picks the group of the proof and the Pedersen commitments: `ristretto255` (the
//! default) or `secp256k1` (Liquid's curve). The proof file
//! records it, and `verify` uses the one recorded (`ristretto255` if the file names none).
//! Scalars (blindings) and commitments are hex in the curve's own encoding.
//!
//! `--transcript` picks the Fiat–Shamir transcript: `merlin` (the default) or `sha256`
//! (SHA-256 only, for verifiers without Keccak such as Simplicity on Liquid). The proof file
//! records it, and `verify` uses the one recorded (`merlin` if the file names none).
//!
//! `--backend` picks the proof system: `bp` (Bulletproofs, the default) or `bppp`
//! (Bulletproofs++, experimental: smaller proofs, faster verification). The verifier reads the
//! backend from the proof and accepts either, unless `verify --backend` requires one.
//!
//! The input file maps the guest's input variables (see `guest/common/bpvm.h`) to values:
//! a number, a decimal or `0x` hex string, an array of those, or (for `uint8_t` arrays) a
//! text string. A private element may be `{"value": .., "blinding": "<hex scalar>"}` to
//! reuse an existing Pedersen commitment; otherwise a random blinding is drawn.
//!
//! `prove` writes the proof file (public: statement data, public I/O, commitments, proof)
//! and the secrets file (values and blindings of all commitments — keep it private).

use std::collections::BTreeMap;
use std::process::ExitCode;

use bpvm_emu::{Image, IoKind, IoType, IoVar, Machine};
use bpvm_zk::isa::Op;
use bpvm_zk::{Backend, Committed, IoSpec, Statement, TranscriptKind};
use bulletproofs::curve::ff::Field as _;
use bulletproofs::curve::{Curve, Field, PointEncoding};
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::curve::{Ristretto, Secp256k1};
use serde_json::{json, Map, Value};

const MAX_STEPS: u64 = 1 << 20;
/// Version of the proof file; 2: the circuit on the fork's builder operations (BP or BP++);
/// 3: witnesses folded into product wires (the fork's API refactor, 2026-10-22).
const PROOF_FILE_VERSION: u64 = 3;
const USAGE: &str = "usage:
  bpvm run    <elf> [-i input.json]
  bpvm prove  <elf> [-i input.json] [-o proof.json] [-s secrets.json] [--backend bp|bppp] [--transcript merlin|sha256] [--curve ristretto255|secp256k1]
  bpvm verify <elf> <proof.json> [--backend bp|bppp]
  bpvm [--no-prove] [--backend bp|bppp] [--transcript merlin|sha256] [--curve ristretto255|secp256k1] <elf> [-i input.json]";

struct Args {
    positional: Vec<String>,
    flags: BTreeMap<String, String>,
    no_prove: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { positional: Vec::new(), flags: BTreeMap::new(), no_prove: false };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--no-prove" => a.no_prove = true,
            "-i" | "-o" | "-s" | "--backend" | "--transcript" | "--curve" => {
                let v = it.next().ok_or(format!("{x} needs a value"))?;
                a.flags.insert(x, v);
            }
            _ if x.starts_with('-') => return Err(format!("unknown flag {x}")),
            _ => a.positional.push(x),
        }
    }
    Ok(a)
}

fn backend_of(a: &Args) -> Result<Backend, String> {
    a.flags.get("--backend").map_or(Ok(Backend::Bp), |b| b.parse().map_err(|e| format!("{b:?}: {e}")))
}

fn transcript_of(a: &Args) -> Result<TranscriptKind, String> {
    a.flags.get("--transcript").map_or(Ok(TranscriptKind::Merlin), |t| t.parse().map_err(|e| format!("{t:?}: {e}")))
}

/// The group of the proof and the commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CurveKind {
    Ristretto255,
    Secp256k1,
}

impl CurveKind {
    fn name(self) -> &'static str {
        match self {
            CurveKind::Ristretto255 => "ristretto255",
            CurveKind::Secp256k1 => "secp256k1",
        }
    }
}

impl std::str::FromStr for CurveKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "ristretto255" | "ristretto" => Ok(CurveKind::Ristretto255),
            "secp256k1" => Ok(CurveKind::Secp256k1),
            _ => Err(format!("unknown curve {s:?} (ristretto255 or secp256k1)")),
        }
    }
}

fn curve_of(a: &Args) -> Result<CurveKind, String> {
    a.flags.get("--curve").map_or(Ok(CurveKind::Ristretto255), |c| c.parse())
}

/// A command line, parsed; the curve is chosen once, for all of it ([`execute`]).
enum Command {
    /// Execute, and prove unless `Mode::Run`.
    Run { path: String, input: Option<String>, mode: Mode },
    /// Verify the proof file `file` (read from `proof_path`) of the ELF at `path`; `require`:
    /// the backend the proof must use.
    Verify { path: String, proof_path: String, file: Value, require: Option<Backend> },
}

fn main() -> ExitCode {
    let res = parse_args().and_then(|a| {
        let p = &a.positional;
        let backend = backend_of(&a)?;
        let kind = transcript_of(&a)?;
        let input = a.flags.get("-i").cloned();
        let run = |path: &str, mode: Mode| Command::Run { path: path.to_string(), input: input.clone(), mode };
        let cmd = match p.first().map(String::as_str) {
            Some("run") if p.len() == 2 => run(&p[1], Mode::Run),
            Some("prove") if p.len() == 2 => {
                let stem = p[1].strip_suffix(".elf").unwrap_or(&p[1]).to_string();
                let out = a.flags.get("-o").cloned().unwrap_or(format!("{stem}.proof.json"));
                let sec = a.flags.get("-s").cloned().unwrap_or(format!("{stem}.secrets.json"));
                run(&p[1], Mode::Prove { out, sec })
            }
            Some("verify") if p.len() == 3 => {
                let file = read_json(&p[2])?;
                Command::Verify { path: p[1].clone(), proof_path: p[2].clone(), file, require: a.flags.contains_key("--backend").then_some(backend) }
            }
            Some(_) if p.len() == 1 => run(&p[0], if a.no_prove { Mode::Run } else { Mode::Demo }),
            _ => return Err(USAGE.into()),
        };
        // the curve: `--curve`, or for `verify` the one the proof file records
        let curve = match &cmd {
            Command::Verify { file, proof_path, .. } => match file.get("curve") {
                None => CurveKind::Ristretto255,
                Some(c) => c.as_str().ok_or(format!("{proof_path}: \"curve\" must be a string"))?.parse().map_err(|e| format!("{proof_path}: {e}"))?,
            },
            Command::Run { .. } => curve_of(&a)?,
        };
        match curve {
            CurveKind::Ristretto255 => execute::<Ristretto>(curve, cmd, backend, kind),
            CurveKind::Secp256k1 => execute::<Secp256k1>(curve, cmd, backend, kind),
        }
    });
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn execute<C: Curve>(curve: CurveKind, cmd: Command, backend: Backend, kind: TranscriptKind) -> Result<(), String> {
    match cmd {
        Command::Run { path, input, mode } => run::<C>(curve, &path, input.as_ref(), mode, backend, kind),
        Command::Verify { path, proof_path, file, require } => verify::<C>(curve, &path, &proof_path, &file, require),
    }
}

enum Mode {
    Run,
    Demo,
    Prove { out: String, sec: String },
}

// ---------- values ----------

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex {s}"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex {s}: {e}"))).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    unhex(s)?.try_into().map_err(|_| format!("expected 32 bytes of hex: {s}"))
}

fn scalar<F: Field>(s: &str) -> Result<F, String> {
    F::from_bytes32(&unhex32(s)?).ok_or(format!("non-canonical scalar {s}"))
}

fn number(v: &Value, ty: IoType) -> Result<u64, String> {
    let x = match v {
        Value::Number(n) => n.as_u64().ok_or(format!("expected a non-negative integer, got {n}"))?,
        Value::String(s) => match s.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16),
            None => s.parse(),
        }
        .map_err(|e| format!("bad number {s:?}: {e}"))?,
        _ => return Err(format!("expected a number, got {v}")),
    };
    let bits = 8 * ty.bytes();
    if bits < 64 && x >> bits != 0 {
        return Err(format!("{x} does not fit in {bits} bits"));
    }
    Ok(x)
}

/// Element values (and optional blindings) of one input variable.
fn parse_input<F: Field>(var: &IoVar, v: &Value) -> Result<Vec<(u64, Option<F>)>, String> {
    let elem = |e: &Value| -> Result<(u64, Option<F>), String> {
        match e {
            Value::Object(o) if var.kind == IoKind::PrivateInput => {
                let value = number(o.get("value").ok_or("missing \"value\"")?, var.ty)?;
                let blinding = match o.get("blinding") {
                    None => None,
                    Some(b) => Some(scalar(b.as_str().ok_or("blinding must be a hex string")?)?),
                };
                Ok((value, blinding))
            }
            _ => Ok((number(e, var.ty)?, None)),
        }
    };
    let mut vals = match v {
        Value::String(s) if var.ty == IoType::U8 && !s.starts_with("0x") => s.bytes().map(|b| (b as u64, None)).collect(),
        Value::Array(a) => a.iter().map(elem).collect::<Result<Vec<_>, _>>()?,
        _ => vec![elem(v)?],
    };
    if var.ty == IoType::U8 && vals.len() < var.count as usize {
        vals.resize(var.count as usize, (0, None)); // zero-pad byte strings
    }
    if vals.len() != var.count as usize {
        return Err(format!("{}: expected {} element(s), got {}", var.name, var.count, vals.len()));
    }
    if var.kind == IoKind::PrivateInput && var.ty == IoType::U8 {
        return Err(format!("{}: private uint8_t inputs are not supported (use uint32_t/uint64_t)", var.name));
    }
    Ok(vals)
}

fn json_values(var: &IoVar, vals: &[u64]) -> Value {
    if var.count == 1 {
        json!(vals[0])
    } else {
        json!(vals)
    }
}

fn read_json(path: &str) -> Result<Value, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&s).map_err(|e| format!("{path}: {e}"))
}

fn write_json(path: &str, v: &Value) -> Result<(), String> {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap() + "\n").map_err(|e| format!("{path}: {e}"))
}

fn patch(img: &mut Image, words: &[(u32, u32)]) -> Result<(), String> {
    for (a, w) in words {
        *img.data.get_mut(a).ok_or(format!("I/O word {a:#x} is outside the RAM image"))? = *w;
    }
    Ok(())
}

fn load(path: &str) -> Result<Image, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Image::from_elf(&bytes)
}

fn vars(img: &Image, kind: IoKind) -> impl Iterator<Item = &IoVar> {
    img.io.iter().filter(move |v| v.kind == kind)
}

/// One entry per element of the private variables of `kind`, in statement order.
fn element_names(img: &Image, kind: IoKind) -> Vec<String> {
    vars(img, kind).flat_map(|v| std::iter::repeat(v.name.clone()).take(v.count as usize)).collect()
}

/// Group per-element JSON values by variable name.
fn group(names: &[String], items: impl IntoIterator<Item = Value>) -> Value {
    let mut m = Map::new();
    for (n, x) in names.iter().zip(items) {
        m.entry(n.clone()).or_insert_with(|| json!([])).as_array_mut().unwrap().push(x);
    }
    Value::Object(m)
}

// ---------- run / prove ----------

fn run<C: Curve>(curve: CurveKind, path: &str, input: Option<&String>, mode: Mode, backend: Backend, kind: TranscriptKind) -> Result<(), String> {
    let mut img = load(path)?;
    println!("loaded {path}: entry {:#x}, {} code words, {} RAM words", img.entry, img.code.len(), img.data.len());

    // Inputs: patch the image, remember public values and private blindings.
    let input = match input {
        Some(p) => read_json(p)?,
        None => json!({}),
    };
    let input = input.as_object().ok_or("the input file must be a JSON object")?.clone();
    for k in input.keys() {
        if !img.io.iter().any(|v| &v.name == k && v.kind.is_input()) {
            return Err(format!("{k:?} is not an input variable of the guest"));
        }
    }
    let mut public_in = Map::new();
    let mut spec = IoSpec::<C::Scalar>::default();
    let mut rng = rand::rngs::OsRng;
    for var in img.io.clone().iter().filter(|v| v.kind.is_input()) {
        let v = input.get(&var.name).ok_or(format!("missing input {:?}", var.name))?;
        let vals = parse_input::<C::Scalar>(var, v)?;
        let plain: Vec<u64> = vals.iter().map(|x| x.0).collect();
        patch(&mut img, &var.to_words(&plain))?;
        if var.kind == IoKind::PublicInput {
            public_in.insert(var.name.clone(), json_values(var, &plain));
        } else {
            for (i, (_, r)) in vals.iter().enumerate() {
                spec.private_in.push((var.words(i as u32), r.unwrap_or_else(|| C::Scalar::random(&mut rng))));
            }
        }
    }
    for var in vars(&img, IoKind::PrivateOutput) {
        if var.ty == IoType::U8 {
            return Err(format!("{}: private uint8_t outputs are not supported", var.name));
        }
        for i in 0..var.count {
            spec.private_out.push((var.words(i), C::Scalar::random(&mut rng)));
        }
    }
    for var in vars(&img, IoKind::PublicOutput) {
        spec.public_out.extend(var.all_words());
    }

    let trace = Machine::from_image(&img).run(MAX_STEPS).map_err(|t| format!("execution trapped: {t:?}"))?;
    println!("executed {} steps, exit code {}", trace.steps.len(), trace.exit_code);
    if let Some(u) = img.stack_usage(&trace) {
        // the stack's words are part of the proven RAM image: its size (STACK_SIZE when the
        // guest is linked) is a cost, and it is public, so a run never chooses it
        println!("stack:    {} of {} bytes touched", u.touched, u.size);
        if u.overflow > 0 {
            eprintln!("warning: the stack pointer went {} bytes below the stack: raise STACK_SIZE (the program overwrote the data below it)", u.overflow);
        }
    }

    let (stmt, wit) = bpvm_zk::witness_with_io::<C>(&img, &trace, &spec)?;
    let mix: Vec<String> = stmt.op_counts.iter().map(|(op, n)| format!("{op:?}×{n}")).collect();
    println!("instruction mix: {}", mix.join(" "));

    // Outputs
    let out_word = |a: u32| stmt.public_out.iter().find(|(b, _)| *b == a).map_or(0, |x| x.1);
    let mut public_out = Map::new();
    for var in vars(&img, IoKind::PublicOutput) {
        public_out.insert(var.name.clone(), json_values(var, &var.from_words(out_word)));
    }
    for (name, val) in &public_out {
        println!("public output  {name} = {val}");
    }
    let (in_names, out_names) = (element_names(&img, IoKind::PrivateInput), element_names(&img, IoKind::PrivateOutput));
    let (open_in, open_out) = wit.openings().split_at(stmt.private_in.len());
    for (n, (c, (v, _))) in out_names.iter().zip(stmt.private_out.iter().zip(open_out)) {
        println!("private output {n} = {v} (commitment {}…)", &hex(c.commitment.as_bytes())[..16]);
    }

    let proved = match mode {
        Mode::Run => return Ok(()),
        _ => bpvm_zk::prove_with(&stmt, &wit, backend, kind).map_err(|e| format!("prover: {e:?}"))?,
    };
    let (proof, stats) = proved;
    match backend {
        Backend::Bp => println!("proved:   bp ({}) on {}, {} multipliers (padded to {}), proof {} bytes, {:.2?}", kind.name(), curve.name(), stats.gates, stats.gens_capacity, stats.proof_bytes, stats.time),
        _ => println!("proved:   bppp ({}) on {}, {} gates, {} linear slots, proof {} bytes, {:.2?}", kind.name(), curve.name(), stats.gates, stats.linear, stats.proof_bytes, stats.time),
    }

    match mode {
        Mode::Run => unreachable!(),
        Mode::Demo => {
            let t = bpvm_zk::verify_with(&stmt, &proof, kind).map_err(|e| format!("verifier rejected: {e:?}"))?;
            println!("verified: program halts with exit code {} after {} steps ({t:.2?})", stmt.exit_code, stmt.steps);
            let mut forged = stmt.clone();
            forged.exit_code ^= 1;
            match bpvm_zk::verify_with(&forged, &proof, kind) {
                Err(_) => println!("sanity:   the same proof is rejected for exit code {}", forged.exit_code),
                Ok(_) => return Err("proof verified against a forged exit code".into()),
            }
        }
        Mode::Prove { out, sec } => {
            let commitment = |c: &Committed<C>| json!(hex(c.commitment.as_bytes()));
            let opening = |(c, (v, r)): (&Committed<C>, &(u64, C::Scalar))| {
                json!({"value": v, "blinding": hex(&r.to_bytes32()), "commitment": hex(c.commitment.as_bytes())})
            };
            let op_counts: Map<String, Value> = stmt.op_counts.iter().map(|(op, n)| (format!("{op:?}"), json!(n))).collect();
            let proof_file = json!({
                "bpvm": PROOF_FILE_VERSION,
                "backend": backend.name(),
                "transcript": kind.name(),
                "curve": curve.name(),
                "steps": stmt.steps,
                "exit_code": stmt.exit_code,
                "op_counts": op_counts,
                "public_inputs": public_in,
                "public_outputs": public_out,
                "private_inputs": group(&in_names, stmt.private_in.iter().map(commitment)),
                "private_outputs": group(&out_names, stmt.private_out.iter().map(commitment)),
                "proof": hex(&proof.to_bytes()),
            });
            let secrets = json!({
                "private_inputs": group(&in_names, stmt.private_in.iter().zip(open_in).map(opening)),
                "private_outputs": group(&out_names, stmt.private_out.iter().zip(open_out).map(opening)),
            });
            write_json(&out, &proof_file)?;
            write_json(&sec, &secrets)?;
            println!("wrote {out} (proof) and {sec} (openings — keep private)");
        }
    }
    Ok(())
}

// ---------- verify ----------

/// `require`: the backend the proof must use (`--backend`); any if `None`. The curve is the
/// one the proof file records.
fn verify<C: Curve>(curve: CurveKind, path: &str, proof_path: &str, f: &Value, require: Option<Backend>) -> Result<(), String> {
    let mut img = load(path)?;
    let get = |k: &str| f.get(k).ok_or(format!("{proof_path}: missing {k:?}"));
    let obj = |k: &str| get(k).and_then(|v| v.as_object().cloned().ok_or(format!("{proof_path}: {k:?} must be an object")));
    let num = |k: &str| get(k).and_then(|v| v.as_u64().ok_or(format!("{proof_path}: {k:?} must be a number")));

    let version = num("bpvm")?;
    if version != PROOF_FILE_VERSION {
        return Err(format!("{proof_path}: proof file version {version}, this bpvm reads version {PROOF_FILE_VERSION}"));
    }
    let proof = R1CSProof::<C>::from_bytes(&unhex(get("proof")?.as_str().ok_or("proof must be a hex string")?)?)
        .map_err(|e| format!("bad proof: {e:?}"))?;
    let named = get("backend")?.as_str().ok_or(format!("{proof_path}: \"backend\" must be a string"))?;
    if named != proof.backend().name() {
        return Err(format!("{proof_path}: the file says backend {named:?}, the proof is {:?}", proof.backend().name()));
    }
    if let Some(b) = require.filter(|b| *b != proof.backend()) {
        return Err(format!("{proof_path}: a {} proof, but --backend {} was required", proof.backend(), b));
    }

    let kind: TranscriptKind = match f.get("transcript") {
        None => TranscriptKind::Merlin,
        Some(t) => t.as_str().ok_or(format!("{proof_path}: \"transcript\" must be a string"))?.parse().map_err(|e| format!("{proof_path}: transcript: {e}"))?,
    };

    let mut op_counts = BTreeMap::new();
    for (name, n) in obj("op_counts")? {
        let op = Op::ALL.iter().find(|o| format!("{o:?}") == name).ok_or(format!("unknown opcode {name}"))?;
        op_counts.insert(*op, n.as_u64().ok_or("op count must be a number")? as usize);
    }

    // Public inputs are patched into the image exactly as the prover did.
    let public_in = obj("public_inputs")?;
    for var in vars(&img, IoKind::PublicInput).cloned().collect::<Vec<_>>() {
        let v = public_in.get(&var.name).ok_or(format!("missing public input {:?}", var.name))?;
        let vals: Vec<u64> = parse_input::<C::Scalar>(&var, v)?.into_iter().map(|x| x.0).collect();
        patch(&mut img, &var.to_words(&vals))?;
    }

    let commitments = |key: &str, kind: IoKind| -> Result<Vec<Committed<C>>, String> {
        let m = obj(key)?;
        let mut out = Vec::new();
        for var in vars(&img, kind) {
            let list = m.get(&var.name).and_then(Value::as_array).ok_or(format!("missing commitments for {:?}", var.name))?;
            if list.len() != var.count as usize {
                return Err(format!("{}: expected {} commitment(s)", var.name, var.count));
            }
            for (i, c) in list.iter().enumerate() {
                let c = c.as_str().ok_or("commitment must be a hex string")?;
                let commitment = C::Compressed::from_slice(&unhex(c)?).ok_or(format!("{}: not a {} point encoding: {c}", var.name, curve.name()))?;
                out.push(Committed { words: var.words(i as u32), commitment });
            }
        }
        Ok(out)
    };
    let private_in = commitments("private_inputs", IoKind::PrivateInput)?;
    let private_out = commitments("private_outputs", IoKind::PrivateOutput)?;

    let public_out_json = obj("public_outputs")?;
    let mut public_out = Vec::new();
    for var in vars(&img, IoKind::PublicOutput) {
        let v = public_out_json.get(&var.name).ok_or(format!("missing public output {:?}", var.name))?;
        let as_input = IoVar { kind: IoKind::PublicInput, ..var.clone() };
        let vals: Vec<u64> = parse_input::<C::Scalar>(&as_input, v)?.into_iter().map(|x| x.0).collect();
        public_out.extend(var.to_words(&vals));
    }

    let exit_code = u32::try_from(num("exit_code")?).map_err(|_| format!("{proof_path}: exit_code does not fit in 32 bits"))?;
    // The verifier builds a circuit of this size: bound it before synthesis.
    let steps = num("steps")?;
    if steps == 0 || steps > MAX_STEPS {
        return Err(format!("{proof_path}: steps must be in 1..={MAX_STEPS}"));
    }
    let steps = steps as usize;
    if op_counts.values().try_fold(0usize, |acc, n| acc.checked_add(*n)) != Some(steps) {
        return Err(format!("{proof_path}: the op counts do not add up to the steps"));
    }
    let stmt = Statement::new(&img, steps, op_counts, exit_code, private_in, private_out, public_out);
    let t = bpvm_zk::verify_with(&stmt, &proof, kind).map_err(|e| format!("verifier rejected: {e:?}"))?;

    println!("verified ({t:.2?}, {}, {}, {}): {path} halts with exit code {} after {} steps", kind.name(), curve.name(), proof.backend(), stmt.exit_code, stmt.steps);
    for (k, v) in &public_in {
        println!("  public input   {k} = {v}");
    }
    for (k, v) in &public_out_json {
        println!("  public output  {k} = {v}");
    }
    for (key, label) in [("private_inputs", "private input "), ("private_outputs", "private output")] {
        for (k, v) in obj(key)? {
            for c in v.as_array().into_iter().flatten() {
                println!("  {label} {k}: commitment {}", c.as_str().unwrap_or("?"));
            }
        }
    }
    Ok(())
}
