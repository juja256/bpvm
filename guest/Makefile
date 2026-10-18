LLVM    ?= /opt/homebrew/opt/llvm/bin
CC      := $(LLVM)/clang
LD      := ld.lld
OBJDUMP := $(LLVM)/llvm-objdump
CFLAGS  := --target=riscv32-unknown-elf -march=rv32im -mabi=ilp32 -O2 \
           -ffreestanding -fno-builtin -nostdlib -fno-pic -mno-relax

all: fib.elf

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

fib.elf: start.o fib.o link.ld
	$(LD) -T link.ld --no-relax start.o fib.o -o $@

dump: fib.elf
	$(OBJDUMP) -d -M no-aliases fib.elf

clean:
	rm -f *.o *.elf
