// bpvm guest I/O.
//
// Declare I/O variables with these macros; the host finds them by name in the ELF symbol
// table and takes the element type from the section name:
//
//   BPVM_PUBLIC_INPUT(uint64_t, fee);          // value from the input file, public
//   BPVM_PRIVATE_INPUT(uint64_t, amounts[2]);  // value from the input file, hidden behind
//                                              // one Pedersen commitment per element
//   BPVM_PUBLIC_OUTPUT(uint32_t, ok);          // final value revealed in the proof
//   BPVM_PRIVATE_OUTPUT(uint64_t, total);      // final value committed, opening goes to
//                                              // the prover's secret file
//
// Element types: uint8_t (public only), uint32_t, uint64_t. Variables are volatile so the
// compiler neither constant-folds inputs nor drops stores to outputs.
#pragma once
#include <stdint.h>

#define BPVM_IO_(kind, T, decl) \
    __attribute__((section(".bpvm." kind "." #T), used, aligned(4))) volatile T decl

#define BPVM_PUBLIC_INPUT(T, decl)   BPVM_IO_("public_input", T, decl)
#define BPVM_PRIVATE_INPUT(T, decl)  BPVM_IO_("private_input", T, decl)
#define BPVM_PUBLIC_OUTPUT(T, decl)  BPVM_IO_("public_output", T, decl)
#define BPVM_PRIVATE_OUTPUT(T, decl) BPVM_IO_("private_output", T, decl)
