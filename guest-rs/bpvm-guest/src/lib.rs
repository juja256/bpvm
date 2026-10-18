//! Minimal runtime for bpvm guests written in Rust.
//!
//! Depend on this crate and define the entry function:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! use bpvm_guest as _;
//!
//! #[no_mangle]
//! extern "C" fn main() -> u32 {
//!     42 // exit code
//! }
//! ```
//!
//! `_start` sets the stack pointer (`__stack_top` from `link.ld`), calls `main` and halts
//! with its return value as the exit code (`ecall` with `a7 = 93`). A panic halts with exit
//! code `0xffffffff`.
//!
//! I/O variables use the same sections as `guest/common/bpvm.h`:
//!
//! ```ignore
//! #[no_mangle]
//! #[link_section = ".bpvm.private_input.u64"]
//! static mut AMOUNTS: [u64; 2] = [0; 2];
//! // read with core::ptr::read_volatile(&raw const AMOUNTS)
//! ```

#![no_std]

core::arch::global_asm!(
    ".section .text.start",
    ".global _start",
    "_start:",
    "la sp, __stack_top",
    "call main",
    "li a7, 93",
    "ecall",
);

/// Halt immediately with `code`.
pub fn exit(code: u32) -> ! {
    unsafe { core::arch::asm!("li a7, 93", "ecall", in("a0") code, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(u32::MAX)
}
