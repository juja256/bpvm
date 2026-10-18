# Build the secp256k1 guest with Homebrew rustc (core built from rust-src).
CARGO := RUSTC_BOOTSTRAP=1 cargo
OUT   := target/riscv32im-unknown-none-elf/release

all: ec_add.elf ec_base.elf ec_mini.elf

ec_add.elf: src/main.rs Cargo.toml link.ld
	$(CARGO) build --release --bin ec-add
	cp $(OUT)/ec-add $@

ec_mini.elf: src/bin/ec-mini.rs Cargo.toml link.ld
	$(CARGO) build --release --bin ec-mini
	cp $(OUT)/ec-mini $@

ec_base.elf: src/main.rs Cargo.toml link.ld
	$(CARGO) build --release --bin ec-add --features baseline --target-dir target/baseline
	cp target/baseline/riscv32im-unknown-none-elf/release/ec-add $@

clean:
	cargo clean; rm -f *.elf
