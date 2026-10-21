# bpvm

Experimental zkVM for RV32IM programs (Rust/C guests) proven with **Bulletproofs** or
**Bulletproofs++** (chosen per proof), with reciprocal-argument (logUp) lookups and memory
checking. The circuit is written once against the `CircuitBuilder` of the
[bulletproofs fork](https://github.com/juja256/bulletproofs) and lowered to either proof
system. See [DESIGN.md](DESIGN.md).

```
crates/bpvm-emu   RV32IM interpreter recording the execution trace, ELF loader
crates/bpvm-zk    the circuit: gadgets (tables, lookups, buses), opcode chips, CPU + memory, prove/verify
crates/bpvm-cli   `bpvm run|prove|verify <elf>`: execute, prove to a JSON proof file, verify
guest/            C guests (fib, sha256, balance, mul) and their runtime -> guest/README.md
guest-rs/         Rust guests (ec-add with k256, ec-mini) and runtime  -> guest-rs/README.md
```

## Quick start

```sh
cargo run --release -p bpvm-cli -- guest/fib/fib.elf          # execute, prove, verify Fibonacci(10) = 55
cargo run --release -p bpvm-cli -- --backend bppp guest/fib/fib.elf   # the same with BP++
cargo run --release -p bpvm-cli -- run guest-rs/ec-add/ec_add.elf   # execute only
cargo test --release
```

The example ELFs are committed. To rebuild them or write your own guest see
[guest/README.md](guest/README.md) (C: Homebrew llvm + lld) and
[guest-rs/README.md](guest-rs/README.md) (Rust: rust-src + lld).

`--features parallel` (on `bpvm-cli` or `bpvm-zk`) enables the multi-threaded prover and
verifier of the bulletproofs fork (rayon); proofs are identical to the serial ones.
The default feature `bppp-vartime` computes the BP++ norm argument in variable time: its inputs
are uniformly random given the transcript, the commitments to the witness stay constant time,
and the proofs are the same (secp256k1-zkp's BP++ does the same). It proves ≈ 13% faster;
`--no-default-features` gives the constant-time norm argument.

**Backends.** `--backend bp` (default) is Bulletproofs: upstream protocol, logUp over
randomized constraints. `--backend bppp` is Bulletproofs++ (ePrint 2022/510, experimental,
not audited): lookups, the bus and the memory argument are native reciprocal arguments, so a
CPU row costs 22 gates instead of 35.5 multipliers; proofs are 400 B smaller and verification
is faster single-threaded. The verifier reads the backend from the proof (`verify --backend`
requires one).

**Transcripts.** `--transcript merlin` (default) is Merlin, as upstream. `--transcript sha256`
uses the fork's `Sha256Transcript`
([docs/sha256-transcript.md](https://github.com/juja256/bulletproofs/blob/main/docs/sha256-transcript.md)):
Fiat–Shamir on SHA-256 alone, so that a verifier without Keccak can recompute the challenges.
The target is a Simplicity verifier on Liquid. Proof sizes and times are the same: fib is
1345 B on BP and 945 B on BP++ either way. The proof file records the transcript, and
`verify` follows it. In code: `bpvm_zk::prove_with` / `verify_with` with a `TranscriptKind`.

Command line:

```
bpvm run    <elf> [-i input.json]                                   execute only
bpvm prove  <elf> [-i input.json] [-o proof.json] [-s secrets.json] [--backend bp|bppp]
            [--transcript merlin|sha256]
bpvm verify <elf> <proof.json> [--backend bp|bppp]
bpvm [--no-prove] [--backend bp|bppp] [--transcript merlin|sha256] <elf> [-i input.json]
                                              demo: prove, verify, reject a forged exit code
```

Developer examples (`cargo run --release -p bpvm-zk --example <name>`): `op_costs`
(BP multipliers and BP++ gates per opcode), `linear_cost` (cost of linear constraints),
`mem_profile <elf> [bp|bppp]` (heap per prover stage), `r1cs_scaling` (prover/verifier time
vs circuit size), `simplicity [<elf>] [name=v1,v2 ...]` (feature `simplicity`: the Simplicity
verifier of a guest's proof over secp256k1, run as a Liquid node would; e.g.
`guest/mul/mul.elf a=100003 b=70001`).

## Inputs and outputs, Pedersen commitments

The guest declares I/O variables with the macros from [`guest/common/bpvm.h`](guest/common/bpvm.h); the
host finds them by name in the ELF symbol table and reads the element type from the section
name, so nothing else has to be configured:

```c
#include "bpvm.h"
BPVM_PRIVATE_INPUT(uint64_t, inputs[2]);   // hidden: one Pedersen commitment per element
BPVM_PRIVATE_INPUT(uint64_t, outputs[2]);
BPVM_PUBLIC_INPUT(uint64_t, fee);          // public: part of the statement
BPVM_PUBLIC_INPUT(uint64_t, max_output);
BPVM_PUBLIC_OUTPUT(uint32_t, ok);          // final value revealed
BPVM_PRIVATE_OUTPUT(uint64_t, total);      // final value committed with a fresh blinding
```

Values go into a JSON file next to the program ([`guest/balance/balance.json`](guest/balance/balance.json)):

```json
{ "inputs": [1000, 2500], "outputs": [3000, 490], "fee": 10, "max_output": 5000 }
```

A private element can be `{"value": 1000, "blinding": "<hex scalar>"}` to reuse a commitment
made elsewhere; otherwise the blinding is random. `uint8_t` arrays (public only) also take a
text string.

```sh
bpvm prove  guest/balance/balance.elf -i guest/balance/balance.json   # -> balance.proof.json, balance.secrets.json
bpvm verify guest/balance/balance.elf guest/balance/balance.proof.json
bpvm guest/mul/mul.elf -i guest/mul/mul.json                         # c = a·b, a and b private, c public
```

- `*.proof.json` is public: step count, opcode counts, exit code, public inputs/outputs,
  the commitments $V_i = v_i B + r_i \tilde B$ (ristretto255, dalek `PedersenGens`) and the
  proof. The verifier rebuilds the statement from the ELF and this file.
- `*.secrets.json` holds the openings $(v_i, r_i)$ of every commitment, inputs and outputs.

The claim is: *there are values opening the input commitments such that the program, with
the public inputs, halts with this exit code, these public outputs and final values opening
the output commitments.* In the circuit a committed input is a group of RAM words whose
initial values are range-checked witnesses $w_k$ with $\sum_k 2^{32k} w_k = v$; outputs bind
final values the same way. Cost: ~5 multipliers per committed 32-bit word, independent of how
the guest reads it. Rust guests use the same section names, e.g.
`#[no_mangle] #[link_section = ".bpvm.private_input.u64"] static mut X: [u64; 2] = [0; 2];`
with volatile access.

## Benchmarks

`cargo run --release -p bpvm-cli [--features parallel] -- --backend bp|bppp <elf>`: execute,
prove, verify (2026-10-20, bulletproofs fork `main` `f9f540a`, unchanged on `5b4439b`; BP++ with the default
`bppp-vartime`). BP size is in
multipliers (padded to a power of two); BP++ size is gates $N_p + N_m$ plus linear slots
$N_{lin}$ (free witnesses, multiplicities and copies; they cost no gate but lengthen the
commitments).

| guest | steps | backend | size | proof | serial prove / verify | parallel prove / verify | parallel RSS |
|---|---|---|---|---|---|---|---|
| [Fibonacci](guest/fib/fib.c) | 78 | BP | 4 424 ($2^{13}$) | 1345 B | 0.51 s / 40 ms | 0.36 s / 37 ms | |
| | | BP++ | 2 450 + 1 683 | 945 B | 0.27 s / 16 ms | 0.22 s / 16 ms | |
| [balance](guest/balance/balance.c) | 72 | BP | 4 769 ($2^{13}$) | 1345 B | 0.49 s / 41 ms | | |
| | | BP++ | 2 368 + 2 579 | 977 B | 0.27 s / 19 ms | | |
| [mul](guest/mul/mul.c) | 18 | BP | 1 572 ($2^{11}$) | 1217 B | 0.17 s / 12 ms | | |
| | | BP++ | 776 + 852 | 849 B | 0.13 s / 8 ms | | |
| [SHA-256](guest/sha256/sha256.c) | 5 904 | BP | 314 536 ($2^{19}$) | 1729 B | 30.7 s / 2.49 s | 4.62 s / 0.43 s | 0.50 GB |
| | | BP++ | 178 651 + 105 359 | 1329 B | 15.6 s / 1.05 s | 2.90 s / 0.37 s | 0.76 GB |
| [ec-mini](guest-rs/ec-mini/src) | 20 713 | BP | 977 716 ($2^{20}$) | 1793 B | 75.8 s / 5.24 s | 11.6 s / 1.06 s | 1.13 GB |
| | | BP++ | 578 989 + 263 047 | 1457 B | 49.5 s / 3.18 s | 8.89 s / 1.09 s | 2.15 GB |
| [ec-add](guest-rs/ec-add/src) | 253 556 | BP | 12 407 583 ($2^{24}$) | 2049 B | did not fit in 24 GB | 166 s / 16.4 s | 10.1 GB |
| | | BP++ | 7 262 452 + 3 529 272 | 1649 B | | 110 s / 16.0 s | 10.9 GB |

The guests (the ELF next to each source):
- **Fibonacci** (C): the 10th Fibonacci number, 55 (the exit code).
- **balance** (C): 4 committed inputs, 1 committed output.
- **mul** (C): knowledge of factors, $c = a \cdot b$ with $a, b$ committed 32-bit inputs and
  $c$ a public 64-bit output (rows measured 2026-10-21).
- **SHA-256** (C): SHA-256("abc"), one block.
- **ec-mini** (Rust, no dependencies): secp256k1 $G + 2G$ (Jacobian addition, checked against
  $3G$).
- **ec-add** (Rust, `k256`): $G + 2G$, decode and `to_affine`.

BP++ proofs are 400 B smaller at every size, and BP++ proves with 40% fewer gates. It proves
faster than BP everywhere: 35–49% single-threaded, 23–39% multi-threaded. It verifies 1.6–2.5x
faster single-threaded. Multi-threaded, the two verifiers are about even: BP++ is faster on fib,
sha256 and `ec_add`, and 3% slower on `ec_mini`. The remaining sequential part of the BP++
verifier is the SHA3 digest of the circuit, which is bound into the transcript before any
challenge. On mid-size circuits BP++ needs more memory (gates and linear slots each carry a
generator); the RSS of the largest runs varies between runs on macOS (allocator caches).

The fork's serial code is also faster than the original prover (`ec_mini`: 76 s / 5.3 s
against 92 s / 14 s). Prover memory went from ≈ 3.4 KB to ≈ 1 KB per BP multiplier, ≈ 320 B
of it the generators. The changes: chunked multiscalar multiplications, no generator copies,
the first inner-product rounds computed from the input generators, a streamed $t(X)$ and
compact constraint storage. This is what made the $2^{24}$ circuit of `ec_add` provable.
The BP verifier uses the same compact constraint storage. It computes its final
multiscalar multiplication over generator slices, with the scalars computed in parallel.
One `k256` point addition is ≈ 14.4k steps (`ec_add` − `ec_add_base`); most of the rest is
the field inversion in `to_affine` ($2G$ is decoded from uncompressed SEC1, which only checks
the curve equation).

### Cost per instruction

`cargo run --release -p bpvm-zk --example op_costs` measures the circuit itself:
$\text{size}(\text{capacity } n+16) - \text{size}(n)$, divided by 16.

On BP, two single witnesses share one multiplier, hence the halves. Every instruction pays
the **CPU row: 35.5 multipliers on BP, 22 gates (+ 6 linear slots) on BP++**. On BP, the row
is made of:
- fetch lookup: 1;
- 14 witness cells: 7;
- register write select: 1;
- `rd` range check: 6;
- three timestamp range checks: 13.5;
- six memory tuples: 6;
- bus: 1.

On BP++, free witnesses and lookup multiplicities take no gate. Each reciprocal term (lookup,
memory tuple, bus tuple) is one gate. The opcode chip comes on top:

| opcodes | BP chip | BP total | BP++ chip | BP++ total (gates + linear) |
|---|---|---|---|---|
| `LUI`, `FENCE`, `ECALL` | 4.5 | 40 | 1 | 23 + 12 |
| `ADD`, `SUB`, `ADDI`, `AUIPC`, `JAL` | 5.5 | 41 | 2 | 24 + 12 |
| `JALR` | 6.5 | 42 | 3 | 25 + 12 |
| `BEQ`, `BNE` | 9.5 | 45 | 5 | 27 + 14 |
| `SLTU`, `SLTIU` | 11.5 | 47 | 6 | 28 + 12 |
| `MUL`, `MULHU` | 12 | 47.5 | 6 | 28 + 13 |
| `BLTU`, `BGEU` | 13.5 | 49 | 8 | 30 + 12 |
| `LW` / `SW` | 19 / 19.5 | 54.5 / 55 | 11 / 11 | 33 + 12 / 33 + 13 |
| `MULHSU` | 20 | 55.5 | 12 | 34 + 13 |
| `SLL`, `SLLI` | 20.5 | 56 | 11 | 33 + 15 |
| `DIVU`, `REMU` | 23 | 58.5 | 14 | 36 + 15 |
| `XOR`, `OR`, `AND` (+ `I`) | 24.5 | 60 | 9 | 31 + 28 |
| `SLT`, `SLTI` | 25.5 | 61 | 16 | 38 + 12 |
| `SRL`, `SRLI` | 26.5 | 62 | 15 | 37 + 15 |
| `MULH` | 27 | 62.5 | 17 | 39 + 13 |
| `BLT`, `BGE` / `LHU` | 27.5 | 63 | 18 / 17 | 40 + 12 / 39 + 13 |
| `LH` / `LBU` / `LB` | 31.5 / 33.5 / 36 | 67 / 69 / 71.5 | 20 / 23 / 25 | 42 / 45 / 47 + 13 |
| `SH` / `SB` | 34.5 / 40.5 | 70 / 76 | 21 / 27 | 43 / 49 + 15 |
| `SRA`, `SRAI` | 36.5 | 72 | 22 | 44 + 17 |
| `DIV`, `REM` | 55 | 90.5 | 38 | 60 + 19 |

The expensive opcodes are signed comparison, bitwise ops (8 nibble lookups), sub-word memory
access and signed division. Bitwise ops gain the most on BP++: 24.5 → 9.

The fixed part is the lookup multiplicities plus ≈ 2 multipliers per RAM word for the memory
boundary:

| | BP multipliers | BP++ gates |
|---|---|---|
| fib | 0.8k | 0.3k |
| sha256 | 1.4k | 0.4k |

Measured averages per step:

| | BP multipliers | BP++ gates + linear slots |
|---|---|---|
| fib | 45.9 | 27.3 + 12.4 |
| sha256 (bitwise-heavy) | 53.0 | 30.2 + 17.5 |

Rule of thumb for BP: ≈ 50 multipliers per executed instruction; per multiplier, single-threaded ≈ 80 µs to prove and
≈ 5 µs to verify, ≈ 10 µs and ≈ 1.1 µs with `parallel` (linear); proof
$2\log_2 n + O(1)$ group elements. For BP++: ≈ 30 gates per instruction, 400 B smaller proofs.

Hardware: MacBook Pro (Mac16,7), Apple M4 Pro (10 performance + 4 efficiency cores), 24 GB RAM,
macOS 26.6; `rustc 1.99.1`, release profile; `parallel` uses all cores via rayon.
