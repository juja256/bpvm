# Build the Rust guests: make -C guest-rs
# core is built from rust-src (Homebrew rustc has no prebuilt RISC-V core), which needs
# RUSTC_BOOTSTRAP=1 on stable; with rustup use `rustup target add riscv32im-unknown-none-elf`.
CARGO := RUSTC_BOOTSTRAP=1 cargo
OUT   := target/riscv32im-unknown-none-elf/release

ELFS := ec-add/ec_add.elf ec-add/ec_add_base.elf ec-mini/ec_mini.elf

all: $(ELFS)

ec-add/ec_add.elf: $(wildcard ec-add/src/*.rs) ec-add/Cargo.toml bpvm-guest/src/lib.rs bpvm-guest/link.ld
	$(CARGO) build --release -p ec-add
	cp $(OUT)/ec-add $@

# Baseline (no addition), separate target dir so both feature sets stay cached.
ec-add/ec_add_base.elf: $(wildcard ec-add/src/*.rs) ec-add/Cargo.toml bpvm-guest/src/lib.rs bpvm-guest/link.ld
	$(CARGO) build --release -p ec-add --features baseline --target-dir target/baseline
	cp target/baseline/riscv32im-unknown-none-elf/release/ec-add $@

ec-mini/ec_mini.elf: $(wildcard ec-mini/src/*.rs) ec-mini/Cargo.toml bpvm-guest/src/lib.rs bpvm-guest/link.ld
	$(CARGO) build --release -p ec-mini
	cp $(OUT)/ec-mini $@

clean:
	cargo clean
	rm -f $(ELFS)

.PHONY: all clean
