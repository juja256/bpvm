# bpvm

Experimental zkVM for RV32IM programs (Rust/C guests) proven with Bulletproofs R1CS and
reciprocal-argument (logUp) lookups and memory checking. See [DESIGN.md](DESIGN.md).

```
crates/bpvm-emu   RV32IM interpreter recording the execution trace, ELF loader
crates/bpvm-zk    the circuit: logUp argument, gadgets, opcode chips, CPU + memory, prove/verify
crates/bpvm-cli   `bpvm <elf>`: execute, prove, verify
guest/            C guest (F(10)), bare-metal runtime, linker script, Makefile (clang + lld)
```

```sh
make -C guest                                   # needs Homebrew llvm + lld
cargo run --release -p bpvm-cli -- guest/fib.elf
cargo test --release
cargo run --release -p bpvm-zk --example r1cs_scaling
```
