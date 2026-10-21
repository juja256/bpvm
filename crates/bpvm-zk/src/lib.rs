//! bpvm-zk: proving RV32IM execution traces with Bulletproofs or Bulletproofs++, with
//! reciprocal (logUp) arguments for lookups, the CPU↔chip bus and memory consistency (the
//! circuit builder of the bulletproofs fork).

pub mod chips;
pub mod gadgets;
pub mod isa;
pub mod vm;

pub use bulletproofs::r1cs::Backend;
pub use vm::{cost, prove, prove_with, verify, verify_with, witness, witness_for, witness_with_io, witness_with_io_for, Committed, IoSpec, Statement, Stats, TranscriptKind, Witness};
