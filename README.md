# bpvm

Experimental zkVM for RV32IM programs (Rust/C guests) proven with Bulletproofs R1CS and
reciprocal-argument (logUp) lookups and memory checking. See [DESIGN.md](DESIGN.md).

```
crates/bpvm-emu   RV32IM interpreter recording the execution trace, ELF loader
crates/bpvm-zk    the circuit: logUp argument, gadgets, opcode chips, CPU + memory, prove/verify
crates/bpvm-cli   `bpvm <elf>`: execute, prove, verify
guest/            C guests: F(10), SHA-256("abc"); bare-metal runtime, linker script, Makefile (clang + lld)
guest-rs/         Rust guests (no_std, core built from rust-src): secp256k1 point addition with k256
                  and a dependency-free version (`make -C guest-rs`, needs ld.lld)
```

```sh
make -C guest                                   # needs Homebrew llvm + lld
cargo run --release -p bpvm-cli -- guest/fib.elf
cargo run --release -p bpvm-cli -- --no-prove guest-rs/ec_add.elf   # execute only
cargo test --release
cargo run --release -p bpvm-zk --example r1cs_scaling
```

## Benchmarks

`cargo run --release -p bpvm-cli -- <elf>`: execute, prove, verify (2026-10-18).

| guest | steps | multipliers (padded) | proof | prove | verify |
|---|---|---|---|---|---|
| `guest/fib.elf` — C, F(10) | 78 | 4 515 ($2^{13}$) | 1345 B | 0.63 s | 0.11 s |
| `guest/sha256.elf` — C, SHA-256("abc"), one block | 5 904 | 314 627 ($2^{19}$) | 1729 B | 38.4 s | 7.0 s |
| `guest-rs/ec_mini.elf` — Rust, dependency-free secp256k1 $G+2G$ (Jacobian add + check against $3G$) | 20 713 | 977 743 ($2^{20}$) | 1793 B | 92.3 s | 14.2 s |
| `guest-rs/ec_add.elf` — Rust, `k256`: $G+2G$, decode + to_affine | 253 556 | ≈ 12.7M (est.) | — | — | — |

`ec_mini` peaks at 3.5 GB RSS. `ec_add` is execution only (`--no-prove`): at ≈ 50 multipliers
per step it needs $2^{24}$ generators and does not fit in 24 GB; one `k256` point addition is
≈ 14.4k steps (`ec_add` − `ec_base`), the rest is the square root in point decoding and the
inversion in `to_affine`.

Rule of thumb: ≈ 50 multipliers per executed instruction, ≈ 80 µs/multiplier to prove and
≈ 5 µs/multiplier to verify (linear), proof $2\log_2 n + O(1)$ group elements.

Hardware: MacBook Pro (Mac16,7), Apple M4 Pro (10 performance + 4 efficiency cores), 24 GB RAM,
macOS 26.6; single-threaded prover, `rustc 1.99.1`, release profile.
