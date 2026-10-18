//! Dependency-free secp256k1 point addition, as a bpvm guest.
//!
//! Field elements are 8 little-endian 32-bit limbs; reduction uses
//! $2^{256} \equiv 2^{32} + 977 \pmod p$. Addition is the generic Jacobian formula
//! add-2007-bl (11M + 5S, no special cases: inputs must be distinct and finite).
//! Computes $G + 2G$ and checks it against the known $3G$ without inverting:
//! $X_3 = x \cdot Z_3^2$, $Y_3 = y \cdot Z_3^3$. Exit code 1 on success.

#![no_std]
#![no_main]

use core::hint::black_box;

use bpvm_guest as _;

type Fe = [u32; 8];

const P: Fe = [0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];

/// Big-endian hex limbs (most significant first) to `Fe`.
const fn fe(be: [u32; 8]) -> Fe {
    [be[7], be[6], be[5], be[4], be[3], be[2], be[1], be[0]]
}

fn geq_p(a: &Fe) -> bool {
    for i in (0..8).rev() {
        if a[i] != P[i] {
            return a[i] > P[i];
        }
    }
    true
}

/// a - p (wrapping), used when a >= p or after an overflow.
fn sub_p(a: &mut Fe) {
    let mut borrow = 0i64;
    for i in 0..8 {
        let d = a[i] as i64 - P[i] as i64 + borrow;
        a[i] = d as u32;
        borrow = d >> 32;
    }
}

fn add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let s = a[i] as u64 + b[i] as u64 + carry;
        r[i] = s as u32;
        carry = s >> 32;
    }
    if carry != 0 || geq_p(&r) {
        sub_p(&mut r);
    }
    r
}

fn sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u32; 8];
    let mut borrow = 0i64;
    for i in 0..8 {
        let d = a[i] as i64 - b[i] as i64 + borrow;
        r[i] = d as u32;
        borrow = d >> 32;
    }
    if borrow != 0 {
        // add p back
        let mut carry = 0u64;
        for i in 0..8 {
            let s = r[i] as u64 + P[i] as u64 + carry;
            r[i] = s as u32;
            carry = s >> 32;
        }
    }
    r
}

fn mul(a: &Fe, b: &Fe) -> Fe {
    // 512-bit schoolbook product
    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let cur = t[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
            t[i + j] = cur as u32;
            carry = cur >> 32;
        }
        t[i + 8] = carry as u32;
    }
    // fold: lo + hi * (2^32 + 977)
    let mut r = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let shifted = if i > 0 { t[7 + i] as u64 } else { 0 };
        let cur = t[i] as u64 + t[8 + i] as u64 * 977 + shifted + carry;
        r[i] = cur as u32;
        carry = cur >> 32;
    }
    let top = carry + t[15] as u64; // < 2^12
    // fold again: r + top * (2^32 + 977)
    let mut c = top * 977;
    let cur = r[0] as u64 + (c & 0xffff_ffff);
    r[0] = cur as u32;
    c = (cur >> 32) + (c >> 32) + top;
    for limb in r.iter_mut().skip(1) {
        let cur = *limb as u64 + c;
        *limb = cur as u32;
        c = cur >> 32;
    }
    if c != 0 {
        // wrapped past 2^256 once more: add 2^32 + 977 (cannot overflow again)
        let cur = r[0] as u64 + 977;
        r[0] = cur as u32;
        let mut c2 = (cur >> 32) + 1;
        for limb in r.iter_mut().skip(1) {
            let cur = *limb as u64 + c2;
            *limb = cur as u32;
            c2 = cur >> 32;
        }
    }
    if geq_p(&r) {
        sub_p(&mut r);
    }
    r
}

fn sqr(a: &Fe) -> Fe {
    mul(a, a)
}

#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// add-2007-bl, https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
#[inline(never)]
fn point_add(p: &Jac, q: &Jac) -> Jac {
    let z1z1 = sqr(&p.z);
    let z2z2 = sqr(&q.z);
    let u1 = mul(&p.x, &z2z2);
    let u2 = mul(&q.x, &z1z1);
    let s1 = mul(&mul(&p.y, &q.z), &z2z2);
    let s2 = mul(&mul(&q.y, &p.z), &z1z1);
    let h = sub(&u2, &u1);
    let h2 = add(&h, &h);
    let i = sqr(&h2);
    let j = mul(&h, &i);
    let rr = sub(&s2, &s1);
    let r = add(&rr, &rr);
    let v = mul(&u1, &i);
    let x3 = sub(&sub(&sqr(&r), &j), &add(&v, &v));
    let s1j = mul(&s1, &j);
    let y3 = sub(&mul(&r, &sub(&v, &x3)), &add(&s1j, &s1j));
    let zs = add(&p.z, &q.z);
    let z3 = mul(&sub(&sub(&sqr(&zs), &z1z1), &z2z2), &h);
    Jac { x: x3, y: y3, z: z3 }
}

const ONE: Fe = [1, 0, 0, 0, 0, 0, 0, 0];

const G: Jac = Jac {
    x: fe([0x79be667e, 0xf9dcbbac, 0x55a06295, 0xce870b07, 0x029bfcdb, 0x2dce28d9, 0x59f2815b, 0x16f81798]),
    y: fe([0x483ada77, 0x26a3c465, 0x5da4fbfc, 0x0e1108a8, 0xfd17b448, 0xa6855419, 0x9c47d08f, 0xfb10d4b8]),
    z: ONE,
};
const G2: Jac = Jac {
    x: fe([0xc6047f94, 0x41ed7d6d, 0x3045406e, 0x95c07cd8, 0x5c778e4b, 0x8cef3ca7, 0xabac09b9, 0x5c709ee5]),
    y: fe([0x1ae168fe, 0xa63dc339, 0xa3c58419, 0x466ceaee, 0xf7f63265, 0x3266d0e1, 0x236431a9, 0x50cfe52a]),
    z: ONE,
};
const G3_X: Fe = fe([0xf9308a01, 0x9258c310, 0x49344f85, 0xf89d5229, 0xb531c845, 0x836f99b0, 0x8601f113, 0xbce036f9]);
const G3_Y: Fe = fe([0x388f7b0f, 0x632de814, 0x0fe337e6, 0x2a37f356, 0x6500a999, 0x34c2231b, 0x6cb9fd75, 0x84b8e672]);

#[no_mangle]
extern "C" fn main() -> u32 {
    let r = point_add(&black_box(G), &black_box(G2));
    let z2 = sqr(&r.z);
    let z3 = mul(&z2, &r.z);
    let ok = r.x == mul(&G3_X, &z2) && r.y == mul(&G3_Y, &z3);
    ok as u32
}
