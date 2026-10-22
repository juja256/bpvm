# C guests

Bare-metal C programs for bpvm: compiled with clang to RV32IM, executed and proven by
`bpvm` (see the [top-level README](../README.md)).

```
common/     shared by all C guests
  bpvm.h      I/O macros (public/private inputs and outputs)
  start.c     _start: set the stack, call main, halt with its return value
  link.ld     memory layout: code at 0x10000, data, 1 KB stack
  rules.mk    build rules included by every example's Makefile
fib/        F(10) through memory (loads, stores, .data, .bss)
sha256/     SHA-256("abc"), one block
balance/    confidential balance check with Pedersen-committed inputs and outputs
mul/        knowledge of factors: c = a · b, a and b private, c public
```

| example | steps | exit code | what it shows |
|---|---|---|---|
| `fib` | 78 | 55 = F(10) | the smallest end-to-end proof |
| `sha256` | 5 904 | 186 = `0xba`, first digest byte | a real hash function, 315k multipliers |
| `balance` | 72 | 0 (balanced) | public and private I/O, commitments, JSON input |
| `mul` | 18 | 0 | private factors, a public 64-bit product (`mul`, `mulhu`); 384 BP++ gates |

## Requirements

Homebrew `llvm` (clang with the RISC-V backend) and `lld`:

```sh
brew install llvm lld
```

`rules.mk` uses `/opt/homebrew/opt/llvm/bin/clang` and `ld.lld` from `PATH`; override with
`make LLVM=/path/to/llvm/bin`.

## Stack size

Every word of the stack is part of the proven RAM image (an initial and a final memory tuple
each), so the stack is sized per guest when it is linked: `STACK_SIZE := <bytes>` in the
guest's `Makefile` (default 1024; `rules.mk` passes it to the linker as `__stack_size`, and
`link.ld` names the region `__stack_bottom`..`__stack_top`). It is a property of the program,
public like its code, and never taken from a run: a run's stack depth may depend on private
inputs. `bpvm run` reports how much of the stack a run touched (`stack: 428 of 512 bytes
touched`) and warns if the stack pointer went below it; choose a size that covers every input.

| guest | `STACK_SIZE` | touched by the example run |
|---|---|---|
| `fib` | 16 | 0 |
| `balance` | 16 | 0 |
| `mul` | 16 | 0 |
| `sha256` | 512 | 428 |

## Build

```sh
make -C guest              # all examples
make -C guest/fib          # one example -> guest/fib/fib.elf
make -C guest/fib dump     # disassembly
make -C guest clean
```

The ELFs are committed, so the commands below also work without the toolchain.

## Run and prove

From the repository root (add `--features parallel` after `cargo run --release` for the
multi-threaded prover):

```sh
# execute only: step count, exit code, instruction mix
cargo run --release -p bpvm-cli -- run guest/fib/fib.elf

# demo: execute, prove, verify, and check that a forged exit code is rejected
cargo run --release -p bpvm-cli -- guest/sha256/sha256.elf

# prove to files, verify from the files
cargo run --release -p bpvm-cli -- prove guest/balance/balance.elf -i guest/balance/balance.json
cargo run --release -p bpvm-cli -- verify guest/balance/balance.elf guest/balance/balance.proof.json
```

`prove` writes `<name>.proof.json` (public: step count, opcode counts, exit code, public I/O,
commitments, proof) and `<name>.secrets.json` (openings of the commitments, keep private)
next to the ELF; `-o` and `-s` choose other paths. The verifier needs only the ELF and the
proof file.

## The examples

**fib** — `N = 10` is `volatile` in `.data` so the compiler cannot fold `fib(N)`; the
memo table lives in `.bss`. Exit code 55.

**sha256** — the message (`"abc"`) and its length are in `.data`, the digest goes to `.bss`;
the exit code is the first digest byte. To hash something else, change `MSG`/`LEN`; one
block is ≈ 5.9k steps, so each further 64-byte block adds about as much.

**balance** — the prover knows two input and two output amounts (`uint64_t`, hidden behind
one Pedersen commitment each); the program checks
$\sum \text{inputs} = \sum \text{outputs} + \text{fee}$ without overflow and
$\text{output} \le \text{max\_output}$ for every output. `fee` and `max_output` are public
inputs, `ok` is a public output, `total` (the sum of inputs) a private output with a fresh
commitment. The values are in `balance.json`:

```json
{ "inputs": [1000, 2500], "outputs": [3000, 490], "fee": 10, "max_output": 5000 }
```

Change an amount so that the transfer does not balance and the program returns 1 with
`ok = 0`; the proof is still valid, it just proves that outcome.

## Writing a C guest

1. Create a directory with the program and a two-line Makefile:

   ```sh
   mkdir guest/hello
   printf 'NAME := hello\ninclude ../common/rules.mk\n' > guest/hello/Makefile
   ```

   ```c
   // guest/hello/hello.c
   int main(void) {
       return 42;          // exit code
   }
   ```

2. `make -C guest/hello`, then `cargo run --release -p bpvm-cli -- guest/hello/hello.elf`.
   Add the name to `EXAMPLES` in `guest/Makefile` to build it with the others.

**I/O.** Include `bpvm.h` and declare variables with the macros; the host finds them by name
in the ELF symbol table and takes the element type from the section name:

```c
#include "bpvm.h"
BPVM_PUBLIC_INPUT(uint32_t, n);            // from the input file, public
BPVM_PRIVATE_INPUT(uint64_t, secret[4]);   // from the input file, one commitment per element
BPVM_PUBLIC_OUTPUT(uint32_t, result);      // revealed in the proof file
BPVM_PRIVATE_OUTPUT(uint64_t, digest[2]);  // committed, opening in the secrets file
```

Element types: `uint8_t` (public only), `uint32_t`, `uint64_t`. The input file is a JSON
object mapping every input variable to a number, a decimal or `0x` hex string, an array
of those, or (for `uint8_t` arrays) a text string. A private element may be
`{"value": 1000, "blinding": "<hex scalar>"}` to reuse an existing commitment.

**Limits of the toy runtime.**
- No libc: `-ffreestanding -fno-builtin -nostdlib`; write your own `memcpy` if needed (the
  compiler may emit calls to it for large struct copies).
- Memory is what the ELF declares: code, `.rodata`, `.data`, `.bss` and the stack (1 KB in
  `common/link.ld`, raise it for deep recursion or large locals). Any access outside these
  segments makes the trace unprovable.
- Naturally aligned loads and stores only; no self-modifying code.
- The only syscall is halt (returning from `main`).
- Cost: ≈ 50 multipliers per executed instruction; bitwise operations, signed division and
  byte/half-word memory accesses are the expensive ones (see the per-opcode table in the
  top-level README).
