//! secp256k1 point addition with the `k256` crate, as a bpvm guest.
//!
//! Computes $R = G + 2G = 3G$, converts it to affine and exits with the first byte of
//! $x(R)$ (`0xf9` = 249). With `--features baseline` it skips the addition ($R = G$, exit
//! code `0x79` = 121), so the step difference between the two ELFs is one addition.

#![no_std]
#![no_main]

use core::hint::black_box;

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint};

core::arch::global_asm!(
    ".section .text.start",
    ".global _start",
    "_start:",
    "la sp, __stack_top",
    "call main",
    "li a7, 93",
    "ecall",
);

/// 2G, uncompressed SEC1.
const TWO_G: [u8; 65] = [
    0x04, // x
    0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
    0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
    // y
    0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39, 0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee,
    0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1, 0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a,
];

#[no_mangle]
extern "C" fn main() -> u32 {
    let g = black_box(ProjectivePoint::GENERATOR);
    let enc = EncodedPoint::from_bytes(black_box(&TWO_G[..])).unwrap();
    let q = ProjectivePoint::from(Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&enc)).unwrap());

    let r = if cfg!(feature = "baseline") { black_box(g) } else { black_box(g + q) };
    let _ = black_box(q);

    let x = r.to_affine().to_encoded_point(false);
    x.as_bytes()[1] as u32
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Halt with a recognisable exit code.
    unsafe { core::arch::asm!("li a0, -1", "li a7, 93", "ecall", options(noreturn)) }
}
