// Knowledge of factors: c = a · b, with a and b private (Pedersen-committed) and c public.
// The 64-bit product takes `mul` and `mulhu`.
#include "bpvm.h"

BPVM_PRIVATE_INPUT(uint32_t, a);
BPVM_PRIVATE_INPUT(uint32_t, b);

BPVM_PUBLIC_OUTPUT(uint64_t, c);

int main(void) {
    c = (uint64_t)a * b;
    return 0;
}
