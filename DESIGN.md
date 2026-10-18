# bpvm — design notes

A zkVM for RV32IM on top of Bulletproofs R1CS (`zero-art-rs/bulletproofs`, a fork of
`zkcrypto/bulletproofs` with the two-phase randomized constraints and a reciprocal-argument
example). Guests are Rust/C programs compiled to `riscv32im`; the prover executes the ELF,
records the trace and proves it in one R1CS instance.

Status (2026-10-18): **toy VM complete for RV32IM** — a C program (`guest/fib.c`, F(10))
compiles with clang/lld, runs, and its execution is proven and verified end to end:

```
$ make -C guest && cargo run --release -p bpvm-cli -- guest/fib.elf
executed 78 steps, exit code 55
proved:   4515 multipliers (padded to 8192), proof 1345 bytes, 0.63 s
verified: program halts with exit code 55 after 78 steps (0.11 s)
sanity:   the same proof is rejected for exit code 54
```

Measured average ≈ 50 multipliers per executed instruction (866-step ALU test: 41.8k
multipliers, 4.9 s prove) including the fixed table costs.

## 0. What is implemented

- `bpvm-emu`: RV32IM interpreter with trace, ELF32 loader, test assembler.
- `bpvm-zk::logup`: one signed reciprocal-sum argument (`LogUp`) used for lookups (`Lookup`
  with committed multiplicities), the CPU→chip bus and memory consistency.
- `bpvm-zk::gadgets`: range checks by byte digits (one $(x,k)$ table for all partial ranges),
  booleans, `is_zero`, sign bit, unsigned/signed comparison, nibble XOR/OR/AND, shift powers.
- `bpvm-zk::chips`: all 47 RV32IM opcodes (incl. signed division with the
  $-2^{31}/-1$ overflow and division by zero, `MULH`/`MULHSU`, `SRA`, byte/half loads and
  stores at every offset).
- `bpvm-zk::vm`: statement, witness generation, CPU chip, memory boundary, prove/verify;
  the statement is absorbed into the transcript (strong Fiat–Shamir).
- Tests: ISA coverage on edge values, `fib.elf`, and five tampered traces (wrong ADD/DIV
  result, wrong loaded value, wrong branch, skipped step) proven by a cheating prover
  (`logup::set_unchecked_prover`) — all rejected by the verifier.

- Guest I/O (`guest/bpvm.h`): public inputs patch the RAM image; private inputs and
  outputs are bound to Pedersen commitments through the memory boundary (`vm.rs`, I/O in the
  module docs); public outputs constrain final values. CLI: `bpvm prove` / `bpvm verify`
  with JSON input, proof and secrets files.

**Public / leaked**: program, step count, per-opcode counts, RAM image layout, exit code,
public I/O, number of committed values.
Values in registers and memory stay hidden (the R1CS proof is zero-knowledge).
**Toy limits**: RAM accesses must stay inside the ELF's non-executable segments (stack is a
`NOLOAD` section in `guest/link.ld`); naturally aligned accesses only; no self-modifying
code; the only syscall is halt; not audited.

## 1. Does this make sense? Cost model

Measured on an Apple M4 Pro, 24 GB (single thread, release, `examples/r1cs_scaling.rs`):

| multipliers $n$ | gens | prove | verify | proof |
|---|---|---|---|---|
| $2^{14}$ | 0.14 s | 1.3 s | 76 ms | 1313 B |
| $2^{16}$ | 0.57 s | 5.1 s | 0.31 s | 1441 B |
| $2^{18}$ | 2.3 s | 20.8 s | 1.25 s | 1569 B |

So ≈ 80 µs/multiplier to prove and ≈ 5 µs/multiplier to verify, **both linear**; proof size
$2\log_2 n + O(1)$ group elements. Extrapolation: $2^{20}$ → ~85 s / ~5 s; $2^{24}$ → ~23 min /
~80 s, and `BulletproofGens` alone would hold $2^{25}$ points in memory (GBs).

With ~30–40 multipliers per RV32IM cycle (§4) the practical envelope is **$10^4$–$10^5$ cycles
per proof**. STARK/sumcheck zkVMs (SP1, RISC Zero, Jolt) do $10^6$–$10^9$ cycles with
recursion. bpvm will not compete on throughput; it is worth building where its properties
matter:

- **ZK by default** and **tiny proofs** (~1.5 KB) with a transparent DL-only setup.
- **Native Pedersen-committed inputs**: `Prover::commit` turns guest inputs into ristretto
  Pedersen commitments $V_j$, so a proof can say "program $P$ accepts the values inside
  these commitments" — a natural fit for confidential-assets style statements.
- Good testbed for reciprocal-argument (logUp) memory checking and chip/bus architecture,
  with a path to a better backend (§6).

Structural limits: verifier time is linear in the trace (no succinct verification), no cheap
recursion (ristretto has no curve cycle; `cortado` gives one step: a curve whose base field is
ristretto's scalar field, i.e. native EC precompiles), and padding to a power of two.

## 2. Architecture

```
guest ELF ──► bpvm-emu (execute) ──► Trace { steps } ──► witness generation per chip
                                                           │
             public: program table, capacities, I/O ───────┤
                                                           ▼
            one R1CS: CPU chip + ALU chips + memory argument, linked by lookups/buses
                                                           ▼
                                           Bulletproofs R1CS proof
```

**Fixed shape.** The constraint system must not depend on the control flow, otherwise the
verifier learns the executed path and effectively re-executes. Hence no "emit the gadget of
the instruction at step $k$". Instead:

- the **CPU chip** has one row per cycle (capacity $T$, padded) and performs fetch, register
  accesses and pc update, uniform for all opcodes;
- each **opcode family** (add/sub, logic, shifts, compare, mul, div/rem, load/store, branch)
  is a separate chip with its own capacity $T_f$ and only the constraints for that family;
- the CPU sends $(\mathsf{clk}, \mathsf{op}, a, b, r)$ to a bus; each chip receives the
  same tuples; bus balance is a reciprocal-sum identity.

The capacities $(T, T_f)$ are public (they leak a coarse instruction mix); bucket them to
powers of two if that matters.

## 3. Reciprocal-argument building blocks (`bpvm-zk`)

**Lookup into a public table** (`Lookup`, done). Queries $q_k$ (phase-1 tuples) and
multiplicities $m_i$ are committed in phase 1; after challenges $\alpha, c$:
$$\sum_k \frac{1}{c+\langle\alpha,q_k\rangle} = \sum_i \frac{m_i}{c+\langle\alpha,t_i\rangle}.$$
Cost: 1 multiplier per query + $|T|/2$ multipliers for the multiplicities; the table side is
a linear combination with public coefficients. The name and idea come from Bulletproofs++
(Eagen–Kanjalkar–Ruffing–Nick 2022); logUp (Haböck 2022) is the same identity.

**Bus / multiset equality** (next): as above but both sides are committed tuples with
multiplicity $\pm 1$:
$\sum_{\text{send}} 1/(c+\langle\alpha,s\rangle) = \sum_{\text{recv}} 1/(c+\langle\alpha,r\rangle)$,
1 multiplier per tuple on each side.

**Memory consistency** (offline memory checking, Blum et al. / Spice style). Registers and
RAM share one address space with a tag: $(\mathsf{space}, \mathsf{addr})$. Every access at
time $t$ (with $t = 4\cdot\mathsf{clk} + \mathsf{slot}$) contributes a read tuple
$(\mathsf{addr}, v_{\text{old}}, t_{\text{prev}})$ and a write tuple
$(\mathsf{addr}, v_{\text{new}}, t)$, with $t_{\text{prev}} < t$ proven by a range lookup on
$t - t_{\text{prev}} - 1$. Then
$$\mathsf{Init} \uplus \mathsf{Writes} = \mathsf{Reads} \uplus \mathsf{Final}$$
as multisets, where $\mathsf{Init}$ holds the initial value of every touched word at time 0
(public for data/rodata, zero elsewhere) and $\mathsf{Final}$ is supplied by the prover. The
code segment is read-only and served by the public **program table** instead (no
self-modifying code).

## 4. Per-cycle cost estimate (multipliers, R1CS)

Values are field elements holding 32-bit words; range checks use byte digits from
`Table::range(8)` or 16-bit limbs from a $2^{16}$ table (32k multipliers fixed cost, worth it
past ~$10^4$ cycles).

| component | per cycle | notes |
|---|---|---|
| fetch | 1 | lookup $(\mathsf{pc}, \mathsf{op}, rd, rs_1, rs_2, \mathsf{imm})$ in the program table |
| registers (2 reads + 1 write) | ~9–12 | read/write tuples + timestamp range checks |
| CPU→chip bus | 2 | send + receive |
| ALU chip (amortised) | 2–8 | add/sub: carry bit + 2 limb lookups; logic: 4 byte-op lookups; mul: limbs of lo/hi |
| RAM access (loads/stores only) | ~6 | plus byte/half selection |
| pc update, selectors | ~3–5 | |
| **total** | **~25–40** | |

## 5. Guest toolchain

C: Homebrew `llvm` (clang with the RISC-V backend) + `lld`, see `guest/Makefile`
(`--target=riscv32-unknown-elf -march=rv32im -mabi=ilp32 -O2 -ffreestanding -nostdlib`).
Rust guests need `rustup target add riscv32im-unknown-none-elf` (tier 2, `no_std`). Guest runtime: `_start` sets `sp`, calls `main`, halts with
`ecall` (`a7 = 93`, exit code in `a0`). Instead of I/O ecalls the guest
uses memory-mapped I/O variables in sections `.bpvm.<kind>.<type>` (`guest/bpvm.h`). ELF loading: map `PT_LOAD` segments; `.text` becomes the program table.

## 6. Backend outlook

- **Bulletproofs++ arithmetic circuits** have the reciprocal argument built in and a norm
  argument that roughly halves the proof and cuts prover work; `secp256k1-zkp` has BP++ range
  proofs. Natural upgrade path.
- **Sumcheck + IPA** (Spartan/Jolt with a Hyrax or Bulletproofs-IPA polynomial commitment)
  exploits the uniformity of the CPU chip: the prover stays DL-only and transparent, and
  verifier work drops from $O(n)$ circuit evaluation to sumcheck plus one MSM.
- Keep the chip/bus layer independent of the backend so it can be swapped.

## 7. Roadmap

- **M0** ✅ interpreter + trace, lookup gadget, scaling benchmark.
- **M1–M3** ✅ bus, CPU chip, memory argument, full RV32IM chips, ELF loader, C guest.
- **M4** ✅ public/private I/O with Pedersen-committed inputs and outputs (memory-mapped,
  no ecalls). Next: Rust guest crate with the same macros; hide the instruction mix (pad
  chips with dummy rows that cancel on the bus).
- **M5** benchmarks (fib, sha256, ...), multi-threaded prover, capacity tuning.
- **M6** BP++ or sumcheck backend.

## Notes on the fork

- `tests/reciprocal.rs::get_multiplicities` hardcodes `n = 64` instead of the `n` parameter
  (wrong multiplicities when `n != 64`).
- The reciprocal table side needs one inverse per table row: batch-invert (done in `Lookup`).
- Range of multiplicities is not checked; fine as long as the number of queries is below the
  field characteristic.
