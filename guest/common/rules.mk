# Shared build rules for C guests. An example's Makefile sets NAME (the guest is
# $(NAME).c in the example's directory) and includes this file.

COMMON  := $(dir $(lastword $(MAKEFILE_LIST)))
LLVM    ?= /opt/homebrew/opt/llvm/bin
CC      := $(LLVM)/clang
LD      := ld.lld
OBJDUMP := $(LLVM)/llvm-objdump
CFLAGS  := --target=riscv32-unknown-elf -march=rv32im -mabi=ilp32 -O2 \
           -ffreestanding -fno-builtin -nostdlib -fno-pic -mno-relax -I$(COMMON)

all: $(NAME).elf

start.o: $(COMMON)start.c
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME).o: $(NAME).c $(COMMON)bpvm.h
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME).elf: start.o $(NAME).o $(COMMON)link.ld
	$(LD) -T $(COMMON)link.ld --no-relax start.o $(NAME).o -o $@

# Disassembly
dump: $(NAME).elf
	$(OBJDUMP) -d -M no-aliases $<

clean:
	rm -f *.o $(NAME).elf

.PHONY: all dump clean
