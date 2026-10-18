//! bpvm-emu: an RV32IM interpreter that records the execution trace proven by bpvm.

pub mod asm;
pub mod cpu;
pub mod decode;
pub mod elf;

pub use cpu::{Machine, MemAccess, Step, Trace, Trap, SYSCALL_HALT};
pub use elf::Image;
pub use decode::{decode, AluOp, BranchOp, Instr, Width};
