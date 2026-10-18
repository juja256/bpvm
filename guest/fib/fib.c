// The 10th Fibonacci number, computed through memory so the proof exercises
// loads, stores, .data and .bss, not just registers.

volatile unsigned N = 10;   // .data: the compiler cannot constant-fold fib(N)
unsigned memo[32];          // .bss

static unsigned fib(unsigned n) {
    memo[0] = 0;
    memo[1] = 1;
    for (unsigned i = 2; i <= n; i++)
        memo[i] = memo[i - 1] + memo[i - 2];
    return memo[n];
}

int main(void) {
    return (int)fib(N);   // exit code = F(10) = 55
}
