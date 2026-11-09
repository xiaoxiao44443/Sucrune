#ifndef SUCRUNE_GUEST_EXEC_H
#define SUCRUNE_GUEST_EXEC_H
#include <stddef.h>
#include <stdint.h>
#include "guest_fds.h"

#define SUCRUNE_GUEST_EXEC_MODE "--sucrune-guest-exec-v5"
#define SUCRUNE_GUEST_EXEC_VERSION 5U
#define SUCRUNE_GUEST_EXEC_MAGIC UINT32_C(0x58454753)
#define SUCRUNE_GUEST_EXEC_TEXT (64U * 1024U)
/* Internal execve may start a compiler with hundreds of source paths.
 * SUCRUNE_GUEST_EXEC_TEXT independently caps all serialized strings. */
#define SUCRUNE_GUEST_EXEC_ARGS 1024U
#define SUCRUNE_GUEST_EXEC_ENV 64U
/* Private same-ABI startup packet. argv to the Android ELF is exactly
 * {installed_runner, MODE, decimal_socket_fd, decimal_expected_parent}.
 * The supervisor sends a single packet then closes its sending endpoint.
 * Text order: project executable path, argv[0..argc), envp[0..envc), each
 * including its NUL terminator. The receiver requires an exact packet size.
 * Relative project paths are valid against the inherited broker cwd.
 * image_fd and optional interp_fd are immutable sealed snapshots with the
 * same bytes validated before host exec. Ownership transfers to receiver.
 * Guest data never appears in Android argv/environ. */
struct sucrune_exec_fd {
    int32_t resource, kind, local_alias, broker_handle;
    int32_t status_flags, pty_kind, pty_number, reserved;
    uint64_t network_token; /* Zero for all non-network resources. */
};
struct sucrune_guest_exec {
    uint32_t magic, version, argc, envc, text_size;
    int32_t broker, image_fd, interp_fd;
    uint32_t linux_jit, build_profile, exec_depth, script, fd_limit; /* script argv[0] names the final guest ELF */
    uint64_t signal_mask, ignored_signals;
    /* Indexed by guest FD. Absent={-1,0,-1,-1}. Live entries have flags 0
     * after exec. A shared resource index denotes one open description.
     * Non-broker kinds carry a unique stable native alias; the receiver
     * duplicates a private canonical FD once per local resource. */
    struct sucrune_exec_fd entries[SUCRUNE_LINUX_FD_LIMIT];
    unsigned char text[SUCRUNE_GUEST_EXEC_TEXT];
};
/* Text follows the inherited descriptor table on the wire. */
#define SUCRUNE_GUEST_EXEC_HEADER offsetof(struct sucrune_guest_exec,entries)
#define SUCRUNE_GUEST_EXEC_PREFIX(limit) (SUCRUNE_GUEST_EXEC_HEADER + sizeof(struct sucrune_exec_fd) * (limit))
/* Trusted path retained at startup from argv[0]. NULL outside packaged runner. */
const char *sucrune_linux_runner_path(void);
#endif
