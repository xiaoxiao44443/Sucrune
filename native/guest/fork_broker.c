/* No libc. Every call enters the guest Linux AArch64 syscall ABI. */
static inline long call(long number, long first, long second, long third, long fourth) {
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    register long x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory","cc");
    return x0;
}
static _Noreturn void finish(long code) {
    (void)call(94, code, 0, 0, 0);
    __builtin_trap();
}
static char path[] = "/fork-open-description";
static char data[32];
_Noreturn void _start(void) {
    unsigned long parent_limit[2],child_limit[2];
    if(call(261,0,7,0,(long)parent_limit)!=0 ||
            parent_limit[0]!=1024 || parent_limit[1]!=parent_limit[0]) finish(79);
    long fd = call(56, -100, (long)path, 0x242, 0600);
    if (fd < 0 || call(64, fd, (long)"A", 1, 0) != 1 ||
            call(35, -100, (long)path, 0, 0) != 0) finish(71);
    long child = call(220, 17, 0, 0, 0);
    if (child < 0) finish(72);
    if (child == 0) {
        /* OpenJDK closes inherited descriptors up to sysconf(_SC_OPEN_MAX)
         * after fork, when the synthetic proc directory cannot enumerate FDs. */
        if(call(261,0,7,0,(long)child_limit)!=0 || child_limit[0]!=parent_limit[0] ||
                child_limit[1]!=parent_limit[1] || call(261,0,7,(long)parent_limit,0)!=-1) finish(80);
        if (call(49, (long)"/fork-cwd", 0, 0, 0) != 0 ||
                call(64, fd, (long)"B", 1, 0) != 1 || call(57, fd, 0, 0, 0) != 0) finish(73);
        finish(42);
    }
    int status = 0;
    if (call(260, child, (long)&status, 0, 0) != child || status != (42 << 8)) finish(74);
    if (call(17, (long)data, sizeof(data), 0, 0) != 2 || data[0] != '/' || data[1] != 0) finish(75);
    if (call(62, fd, 0, 1, 0) != 2 || call(64, fd, (long)"C", 1, 0) != 1 ||
            call(62, fd, 0, 0, 0) != 0 || call(63, fd, (long)data, 3, 0) != 3 ||
            data[0] != 'A' || data[1] != 'B' || data[2] != 'C') finish(76);
    if (call(57, fd, 0, 0, 0) != 0) finish(77);
    const char line[] = "fork-broker-ofd-ok\n";
    if (call(64, 1, (long)line, sizeof(line) - 1, 0) != sizeof(line) - 1) finish(78);
    finish(0);
}
