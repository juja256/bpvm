# Rust guests

`no_std` Rust programs for bpvm, compiled for `riscv32im-unknown-none-elf` and proven by
`bpvm` (see the [top-level README](../README.md)). This directory is a separate cargo
workspace: it targets RISC-V, the host workspace does not.

```
bpvm-guest/   runtime crate: _start, halt, panic handler, linker script (16 KB stack)
ec-add/       secp256k1 G + 2G with the `k256` crate; feature `baseline` skips the addition
ec-mini/      secp256k1 G + 2G, dependency-free (32-bit limbs, Jacobian coordinates)
.cargo/       target, linker and build-std settings
Makefile      builds every ELF into its crate directory
```

| example | ELF | steps | exit code | what it shows |
|---|---|---|---|---|
| `ec-add` | `ec-add/ec_add.elf` | 253 556 | 249 = `0xf9`, first byte of $x(3G)$ | an off-the-shelf crate (`k256`) runs unmodified; $2^{24}$ multipliers |
| `ec-add` (`baseline`) | `ec-add/ec_add_base.elf` | 239 161 | 121 = `0x79`, first byte of $x(G)$ | the difference to `ec_add` is the cost of one addition (≈ 14.4k steps) |
| `ec-mini` | `ec-mini/ec_mini.elf` | 20 713 | 1 (result equals $3G$) | the same addition, hand-written: provable in seconds |

## Requirements

- a Rust toolchain with the `rust-src` component (Homebrew `rust` ships it; with rustup:
  `rustup component add rust-src`);
- `ld.lld` (`brew install lld`).

`core` is built from source for the RISC-V target (`build-std` in `.cargo/config.toml`), which
needs `RUSTC_BOOTSTRAP=1` on a stable toolchain; the Makefile sets it.

## Build

```sh
make -C guest-rs            # all ELFs
make -C guest-rs clean
# or one crate by hand:
cd guest-rs && RUSTC_BOOTSTRAP=1 cargo build --release -p ec-mini
# -> guest-rs/target/riscv32im-unknown-none-elf/release/ec-mini
```

The ELFs are committed, so the commands below also work without the toolchain.

## Run and prove

From the repository root:

```sh
cargo run --release -p bpvm-cli -- run guest-rs/ec-add/ec_add.elf          # execute only
cargo run --release -p bpvm-cli --features parallel -- guest-rs/ec-mini/ec_mini.elf
```

`ec_mini` proves in ≈ 10 s with `parallel` (≈ 76 s single-threaded), ≈ 1.1 GB. `ec_add` is a
$2^{24}$-multiplier circuit: ≈ 2.5 minutes to prove, 17 s to verify and ≈ 10 GB with
`parallel`.

## The examples

**ec-add** — computes $R = G + 2G$ with `k256::ProjectivePoint`, converts it to affine and
returns the first byte of $x(R)$. $2G$ is decoded from uncompressed SEC1 bytes (`black_box`
keeps the compiler from evaluating anything at compile time). Most of the 239k baseline
steps are the field inversion in `to_affine`; one point addition is ≈ 14.4k steps.

**ec-mini** — field elements as 8 × 32-bit limbs with the reduction
$2^{256} \equiv 2^{32} + 977 \pmod p$, the add-2007-bl formula in Jacobian coordinates, and
a check of the result against the known $3G$ without inversion
($X = x Z^2$, $Y = y Z^3$). Exits with 1 if the result is right.

## Writing a Rust guest

1. Create a crate and add it to `members` in `guest-rs/Cargo.toml`:

   ```toml
   # guest-rs/hello/Cargo.toml
   [package]
   name = "hello"
   version = "0.1.0"
   edition.workspace = true
   publish.workspace = true

   [dependencies]
   bpvm-guest = { path = "../bpvm-guest" }
   ```

   ```rust
   // guest-rs/hello/src/main.rs
   #![no_std]
   #![no_main]

   use bpvm_guest as _; // entry point, panic handler, linker script

   #[no_mangle]
   extern "C" fn main() -> u32 {
       42 // exit code
   }
   ```

2. `cd guest-rs && RUSTC_BOOTSTRAP=1 cargo build --release -p hello`, then
   `cargo run --release -p bpvm-cli -- guest-rs/target/riscv32im-unknown-none-elf/release/hello`
   from the repository root. Add a rule to the Makefile to copy the ELF next to the crate.

**I/O.** Same sections as the C macros in `guest/common/bpvm.h`
(`.bpvm.<public|private>_<input|output>.<u8|u32|u64>`), on `#[no_mangle]` statics accessed
with volatile reads and writes:

```rust
#[no_mangle]
#[link_section = ".bpvm.private_input.u64"]
static mut AMOUNTS: [u64; 2] = [0; 2];

#[no_mangle]
#[link_section = ".bpvm.public_output.u32"]
static mut OK: u32 = 0;

let a = unsafe { core::ptr::read_volatile(&raw const AMOUNTS) };
unsafe { core::ptr::write_volatile(&raw mut OK, 1) };
```

The input file and the `prove`/`verify` commands are the same as for C guests (see
[guest/README.md](../guest/README.md)).

**Limits of the toy runtime.**
- `no_std`, no allocator: crates that need `alloc` do not work as is.
- Memory is what the ELF declares; the stack is 16 KB (`bpvm-guest/link.ld`). Any access
  outside the ELF segments makes the trace unprovable.
- Naturally aligned accesses only; the only syscall is halt. A panic halts with exit code
  `0xffffffff`.
- Cost: ≈ 50 multipliers per executed instruction. 256-bit arithmetic on 32-bit limbs is
  expensive (each `MUL`/`MULHU` pair plus carries), which is why `ec-add` is large.
