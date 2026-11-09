#include <asm/unistd.h>

/* The filter matches this particular syscall's resume address, so libc and
 * pthread teardown can still issue real getpid calls on the filtered thread.
 * The kernel has already advanced PC when SIGSYS is delivered: the handler
 * must set the result register, not advance PC again.
 */
.text
.p2align 4
.global sucrune_probe_getpid
.hidden sucrune_probe_getpid
.global sucrune_probe_resume
.hidden sucrune_probe_resume

#if defined(__aarch64__)
.type sucrune_probe_getpid, %function
sucrune_probe_getpid:
    mov x8, #__NR_getpid
    svc #0
sucrune_probe_resume:
    ret
.size sucrune_probe_getpid, .-sucrune_probe_getpid
.section .note.GNU-stack,"",%progbits
#elif defined(__x86_64__)
.type sucrune_probe_getpid, @function
sucrune_probe_getpid:
    mov $__NR_getpid, %eax
    syscall
sucrune_probe_resume:
    ret
.size sucrune_probe_getpid, .-sucrune_probe_getpid
.section .note.GNU-stack,"",@progbits
#else
#error "Sucrune's initial probe supports only arm64 and x86_64."
#endif
