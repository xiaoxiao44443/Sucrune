#ifndef SUCRUNE_GUEST_FAULT_H
#define SUCRUNE_GUEST_FAULT_H

/* ARM64 Linux rt_sigframe inputs. The Android C build verifies each offset. */
#define SUCRUNE_FAULT_UC_PC 440
#define SUCRUNE_FAULT_SI_CODE 8
#define SUCRUNE_FAULT_SI_ADDR 16

#ifndef __ASSEMBLER__
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>
struct sucrune_fault_interval { uintptr_t base, size; };
struct sucrune_fault_snapshot {
    struct sucrune_fault_interval ranges[4]; /* Main ELF, PT_INTERP, ET_EXEC island, main arena. */
};
_Static_assert(offsetof(ucontext_t,uc_mcontext.pc)==SUCRUNE_FAULT_UC_PC, "ARM64 fault PC offset");
_Static_assert(offsetof(siginfo_t,si_code)==SUCRUNE_FAULT_SI_CODE, "ARM64 fault code offset");
_Static_assert(offsetof(siginfo_t,si_addr)==SUCRUNE_FAULT_SI_ADDR, "ARM64 fault address offset");
_Static_assert(sizeof(struct sucrune_fault_interval)==16U, "ARM64 fault interval layout");
extern _Atomic(const struct sucrune_fault_snapshot *) sucrune_fault_map;
void sucrune_guest_trace_fault(int signo, siginfo_t *info, void *context);
#endif
#endif
