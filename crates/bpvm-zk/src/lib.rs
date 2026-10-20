//! bpvm-zk: proving RV32IM execution traces with Bulletproofs or Bulletproofs++, with
//! reciprocal (logUp) arguments for lookups, the CPU↔chip bus and memory consistency (the
//! circuit builder of the bulletproofs fork).

pub mod chips;
pub mod gadgets;
pub mod isa;
pub mod vm;

pub use bulletproofs::r1cs::Backend;
pub use vm::{cost, prove, verify, witness, witness_with_io, Committed, IoSpec, Statement, Stats, Witness};
