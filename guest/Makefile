LLVM    ?= /opt/homebrew/opt/llvm/bin
CC      := $(LLVM)/clang
LD      := ld.lld
OBJDUMP := $(LLVM)/llvm-objdump
CFLAGS  := --target=riscv32-unknown-elf -march=rv32im -mabi=ilp32 -O2 \
           -ffreestanding -fno-builtin -nostdlib -fno-pic -mno-relax

all: fib.elf sha256.elf

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.elf: start.o %.o link.ld
	$(LD) -T link.ld --no-relax start.o $*.o -o $@

dump-%: %.elf
	$(OBJDUMP) -d -M no-aliases $<

clean:
	rm -f *.o *.elf

.PRECIOUS: %.o
