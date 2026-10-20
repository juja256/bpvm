//! Heap profile of proving a guest: live bytes after each stage and the peak.
//! `cargo run --release -p bpvm-zk --example mem_profile -- guest/sha256/sha256.elf [bp|bppp]`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use bpvm_emu::{Image, Machine};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let n = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(n, Relaxed);
        ALLOCS.fetch_add(1, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            let n = LIVE.fetch_add(new - l.size(), Relaxed) + new - l.size();
            PEAK.fetch_max(n, Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - new, Relaxed);
        }
        System.realloc(p, l, new)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn mb(x: usize) -> String {
    format!("{:.0} MB", x as f64 / 1e6)
}

/// Live bytes now and the peak since the previous report.
fn report(stage: &str, n: Option<usize>) {
    static T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    let now = std::time::Instant::now();
    T0.get_or_init(|| now);
    let dt = LAST.lock().unwrap().replace(now).map_or(0.0, |t| (now - t).as_secs_f64());
    let (live, peak) = (LIVE.load(Relaxed), PEAK.swap(LIVE.load(Relaxed), Relaxed));
    let per = n.map(|n| format!(" ({:.0} B/multiplier live, {:.0} peak)", live as f64 / n as f64, peak as f64 / n as f64)).unwrap_or_default();
    print!("{dt:>7.2}s ");
    println!("{stage:<14} live {:>8}  peak {:>8}  allocs {}{per}", mb(live), mb(peak), ALLOCS.load(Relaxed));
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: mem_profile <elf> [bp|bppp]");
    let backend: bpvm_zk::Backend = std::env::args().nth(2).map_or(bpvm_zk::Backend::Bp, |b| b.parse().expect("bp or bppp"));
    let img = Image::from_elf(&std::fs::read(&path).unwrap()).unwrap();
    let trace = Machine::from_image(&img).run(1 << 22).unwrap();
    report("executed", None);
    let (st, wit) = bpvm_zk::witness(&img, &trace).unwrap();
    drop(trace);
    report("witness", None);
    let cost = bpvm_zk::cost(&st).unwrap();
    let n = cost.gates(backend);
    PEAK.store(LIVE.load(Relaxed), Relaxed);
    report("sized", Some(n));
    let (proof, stats) = bpvm_zk::vm::prove_staged(&st, &wit, backend, |s| report(s, Some(n))).unwrap();
    report("proved", Some(n));
    let t = bpvm_zk::verify(&st, &proof).unwrap();
    report("verified", Some(n));
    println!("verify {t:.2?}");
    println!("{backend:?}: {} steps, {n} multipliers/gates, {} linear, {} B, prove {:.2?}", st.steps, stats.linear, stats.proof_bytes, stats.time);
}
