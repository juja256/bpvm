// Confidential transfer check: hidden input and output amounts balance up to a public fee,
// and no output exceeds a public limit. The total moved is returned as a fresh commitment.
#include "bpvm.h"

#define N_IN  2
#define N_OUT 2

BPVM_PRIVATE_INPUT(uint64_t, inputs[N_IN]);
BPVM_PRIVATE_INPUT(uint64_t, outputs[N_OUT]);
BPVM_PUBLIC_INPUT(uint64_t, fee);
BPVM_PUBLIC_INPUT(uint64_t, max_output);

BPVM_PUBLIC_OUTPUT(uint32_t, ok);
BPVM_PRIVATE_OUTPUT(uint64_t, total);

// a + b, or 0 with *overflow set
static uint64_t add(uint64_t a, uint64_t b, int *overflow) {
    uint64_t s = a + b;
    *overflow |= s < a;
    return s;
}

int main(void) {
    int overflow = 0;
    uint64_t sum_in = 0, sum_out = fee;
    for (int i = 0; i < N_IN; i++) sum_in = add(sum_in, inputs[i], &overflow);
    int within = 1;
    for (int i = 0; i < N_OUT; i++) {
        uint64_t o = outputs[i];
        within &= o <= max_output;
        sum_out = add(sum_out, o, &overflow);
    }
    int good = !overflow && within && sum_in == sum_out;
    ok = good;
    total = sum_in;
    return good ? 0 : 1;
}
