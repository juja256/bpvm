// Minimal bare-metal runtime: set up the stack, call main, halt with its return value.
// Halt is `ecall` with a7 = 93 (Linux `exit`), exit code in a0.

int main(void);

__attribute__((naked, noreturn, section(".text.start"))) void _start(void) {
    __asm__ volatile(
        "la   sp, __stack_top\n"
        "call main\n"
        "li   a7, 93\n"
        "ecall\n");
}
