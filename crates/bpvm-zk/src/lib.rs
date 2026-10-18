//! bpvm-zk: proving RV32IM execution traces with Bulletproofs R1CS and reciprocal
//! (logUp) arguments for lookups, the CPU↔chip bus and memory consistency.

pub mod chips;
pub mod gadgets;
pub mod isa;
pub mod logup;
pub mod vm;

pub use logup::{LogUp, Lookup, Table};
pub use vm::{prove, verify, witness, witness_with_io, Committed, IoSpec, Statement, Stats, Witness};
