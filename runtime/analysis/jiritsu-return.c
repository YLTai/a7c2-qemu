/* Own return-only constructor receipt. No files, imports, threads or exit. */
void _init(void) {
    static const char receipt[] = "JIRITSU_RETURN=1\n";
    register long x0 __asm__("x0") = 1;
    register long x1 __asm__("x1") = (long)receipt;
    register long x2 __asm__("x2") = sizeof(receipt) - 1;
    register long x8 __asm__("x8") = 64; /* AArch64 write, fixed inherited result FD. */
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
}
