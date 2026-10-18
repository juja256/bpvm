# bpvm

Experimental zkVM for RV32IM programs (Rust/C guests) proven with Bulletproofs R1CS and
reciprocal-argument (logUp) lookups and memory checking. See [DESIGN.md](DESIGN.md).

```
crates/bpvm-emu   RV32IM interpreter recording the execution trace, ELF loader
crates/bpvm-zk    the circuit: logUp argument, gadgets, opcode chips, CPU + memory, prove/verify
crates/bpvm-cli   `bpvm run|prove|verify <elf>`: execute, prove to a JSON proof file, verify
guest/            C guests: F(10), SHA-256("abc"), confidential balance check; bpvm.h (I/O),
                  bare-metal runtime, linker script, Makefile (clang + lld)
guest-rs/         Rust guests (no_std, core built from rust-src): secp256k1 point addition with k256
                  and a dependency-free version (`make -C guest-rs`, needs ld.lld)
```

```sh
make -C guest                                   # needs Homebrew llvm + lld
cargo run --release -p bpvm-cli -- guest/fib.elf
cargo run --release -p bpvm-cli -- --no-prove guest-rs/ec_add.elf   # execute only
cargo test --release
cargo run --release -p bpvm-zk --example r1cs_scaling
cargo run --release -p bpvm-zk --example mem_profile -- guest/sha256.elf   # heap per prover stage
```

`--features parallel` (on `bpvm-cli` or `bpvm-zk`) enables the multi-threaded prover and
verifier of the bulletproofs fork (rayon); proofs are identical to the serial ones.

## Inputs and outputs, Pedersen commitments

The guest declares I/O variables with the macros from [`guest/bpvm.h`](guest/bpvm.h); the
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

Values go into a JSON file next to the program ([`guest/balance.json`](guest/balance.json)):

```json
{ "inputs": [1000, 2500], "outputs": [3000, 490], "fee": 10, "max_output": 5000 }
```

A private element can be `{"value": 1000, "blinding": "<hex scalar>"}` to reuse a commitment
made elsewhere; otherwise the blinding is random. `uint8_t` arrays (public only) also take a
text string.

```sh
bpvm prove  guest/balance.elf -i guest/balance.json   # -> balance.proof.json, balance.secrets.json
bpvm verify guest/balance.elf guest/balance.proof.json
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

`cargo run --release -p bpvm-cli [--features parallel] -- <elf>`: execute, prove, verify
(2026-10-18). Serial: the original single-threaded prover; parallel: the optimised fork
(`zero-art-rs/bulletproofs` 52cecec) with `--features parallel`.

| guest | steps | multipliers (padded) | proof | serial prove / verify | parallel prove / verify | parallel RSS |
|---|---|---|---|---|---|---|
| `guest/fib.elf` — C, F(10) | 78 | 4 515 ($2^{13}$) | 1345 B | 0.63 s / 0.11 s | 0.29 s / 0.04 s | |
| `guest/balance.elf` — C, 4 committed inputs, 1 committed output | 72 | 4 864 ($2^{13}$) | 1345 B | 0.63 s / 0.11 s | 0.27 s / 0.04 s | |
| `guest/sha256.elf` — C, SHA-256("abc"), one block | 5 904 | 314 627 ($2^{19}$) | 1729 B | 38.4 s / 7.0 s | 6.0 s / 0.88 s | 0.74 GB |
| `guest-rs/ec_mini.elf` — Rust, dependency-free secp256k1 $G+2G$ (Jacobian add + check against $3G$) | 20 713 | 977 743 ($2^{20}$) | 1793 B | 92.3 s / 14.2 s (3.5 GB) | 14.0 s / 2.1 s | 1.5 GB |
| `guest-rs/ec_add.elf` — Rust, `k256`: $G+2G$, decode + to_affine | 253 556 | 12 407 610 ($2^{24}$) | 2049 B | did not fit in 24 GB | 215 s / 35 s | 9.4 GB |

Prover memory went from ≈ 3.4 KB to ≈ 1.2 KB per multiplier (chunked multiscalar
multiplications, no generator copies in the inner-product argument, streamed $t(X)$,
compact constraint storage), which is what made the $2^{24}$ circuit of `ec_add` provable.
One `k256` point addition is ≈ 14.4k steps (`ec_add` − `ec_base`); the rest is the square
root in point decoding and the inversion in `to_affine`.

### Multipliers per instruction

`cargo run --release -p bpvm-zk --example op_costs` measures the circuit itself:
$\text{size}(\text{capacity } n+16) - \text{size}(n)$, divided by 16 (two single
allocations share one multiplier, hence the halves). Every instruction pays the **CPU row,
35.5 multipliers**: fetch lookup 1, 14 witness cells 7, register write select 1,
`rd` range check 6, three timestamp range checks 13.5, six memory tuples 6, bus 1. The
opcode chip comes on top:

| opcodes | chip | total |
|---|---|---|
| `LUI`, `FENCE`, `ECALL` | 4.5 | 40 |
| `ADD`, `SUB`, `ADDI`, `AUIPC`, `JAL` | 5.5 | 41 |
| `JALR` | 6.5 | 42 |
| `BEQ`, `BNE` | 9.5 | 45 |
| `SLTU`, `SLTIU` | 11.5 | 47 |
| `MUL`, `MULHU` | 12 | 47.5 |
| `BLTU`, `BGEU` | 13.5 | 49 |
| `LW` / `SW` | 19 / 19.5 | 54.5 / 55 |
| `MULHSU` | 20 | 55.5 |
| `SLL`, `SLLI` | 20.5 | 56 |
| `DIVU`, `REMU` | 23 | 58.5 |
| `XOR`, `OR`, `AND` (+ `I`) | 24.5 | 60 |
| `SLT`, `SLTI` | 25.5 | 61 |
| `SRL`, `SRLI` | 26.5 | 62 |
| `MULH` | 27 | 62.5 |
| `BLT`, `BGE`, `LHU` | 27.5 | 63 |
| `LH` / `LBU` / `LB` | 31.5 / 33.5 / 36 | 67 / 69 / 71.5 |
| `SH` / `SB` | 34.5 / 40.5 | 70 / 76 |
| `SRA`, `SRAI` | 36.5 | 72 |
| `DIV`, `REM` | 55 | 90.5 |

Signed comparison, bitwise ops (8 nibble lookups), sub-word memory access and signed
division are the expensive ones. Fixed part: lookup multiplicities and ≈ 2 multipliers per
RAM word for the memory boundary (fib 0.9k, sha256 1.5k, ec_mini 9.6k with a 16 KB stack).
Measured averages: fib 45.9, sha256 53.0 (bitwise-heavy), ec_mini 46.7 per step.

Rule of thumb: ≈ 50 multipliers per executed instruction; per multiplier ≈ 80 µs to prove
and ≈ 5 µs to verify single-threaded, ≈ 14 µs and ≈ 2 µs with `parallel` (linear); proof
$2\log_2 n + O(1)$ group elements.

Hardware: MacBook Pro (Mac16,7), Apple M4 Pro (10 performance + 4 efficiency cores), 24 GB RAM,
macOS 26.6; `rustc 1.99.1`, release profile; `parallel` uses all cores via rayon.
