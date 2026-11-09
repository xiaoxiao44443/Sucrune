#ifndef SUCRUNE_WORKSPACE_BROKER_H
#define SUCRUNE_WORKSPACE_BROKER_H
#include <stddef.h>
#include <stdint.h>
#define SUCRUNE_BROKER_MAGIC 0x53554352U
#define SUCRUNE_IO_LIMIT 4096U
#define SUCRUNE_BULK_READ_LIMIT (1U << 20)
/* BEGIN {handle,length,positioned,offset}, empty payload. A single regular-file
 * read/pread takes the snapshot; result is its full length (including zero),
 * size is the first packet length. NEXT {} returns its packet length in both
 * result and size, or -ENOENT once drained. ABORT {} is idempotent. A second
 * BEGIN while an unread tail exists returns -EBUSY. Snapshots are session-local. */
#define SUCRUNE_BROKER_BULK_READ  0x53554201U
#define SUCRUNE_BROKER_BULK_NEXT  0x53554202U
#define SUCRUNE_BROKER_BULK_ABORT 0x53554203U
/* Upload to a session-local buffer before performing one write/pwrite.
 * WRITE {handle, length, positioned, offset} reserves the target. PUSH
 * {offset_in_buffer,0,0,0} appends bytes. COMMIT {} returns the actual
 * kernel write count and consumes the upload. DROP {} is idempotent. */
#define SUCRUNE_BULK_WRITE_LIMIT (1U << 20)
#define SUCRUNE_BUILD_BULK_WRITE_LIMIT (16U << 20)
#define SUCRUNE_BROKER_BULK_WRITE  0x53554210U
#define SUCRUNE_BROKER_BULK_PUSH   0x53554211U
#define SUCRUNE_BROKER_BULK_COMMIT 0x53554212U
#define SUCRUNE_BROKER_BULK_DROP   0x53554213U
#define SUCRUNE_PATH_LIMIT 1024U
#define SUCRUNE_DEFAULT_FILE_RESOURCES 64U
#define SUCRUNE_FILE_RESOURCES 1024U
enum sucrune_workspace_profile { SUCRUNE_WORKSPACE_BUNDLED, SUCRUNE_WORKSPACE_LINUX, SUCRUNE_WORKSPACE_BUILD };
/* Manager-selected for a broker and all of its descendants. PROJECT grants
 * writes under guest /workspace and /tmp. READ_ONLY grants no filesystem writes. */
enum sucrune_write_scope { SUCRUNE_WRITE_UNRESTRICTED, SUCRUNE_WRITE_READ_ONLY, SUCRUNE_WRITE_PROJECT };
#define SUCRUNE_BROKER_HANDLE_BASE 3U
/* Positioned file I/O uses args {opaque_handle, byte_count, offset, 0}.
 * pread64 (67) requires no payload; pwrite64 (68) requires byte_count bytes.
 * Counts are bounded by SUCRUNE_IO_LIMIT; offsets and their exclusive end
 * must fit nonnegative off_t. Neither operation changes the shared offset. */
#define SUCRUNE_BROKER_PREAD64 67U
#define SUCRUNE_BROKER_PWRITE64 68U
/* Regular project file -> regular project file. args = {output_handle,
 * input_handle, count, input_offset}; -1 selects the input OFD position.
 * One kernel transfer returns a byte count with no payload. */
#define SUCRUNE_BROKER_SENDFILE 71U
/* flock: args={opaque_handle, operation, 0, 0}, no payload. Supports real
 * kernel LOCK_SH/LOCK_EX with LOCK_NB and LOCK_UN; blocking acquisition is
 * explicitly unsupported. Dup aliases share the same open description and
 * final close (including broker EOF) releases its locks. */
#define SUCRUNE_BROKER_FLOCK 32U
#define SUCRUNE_BROKER_RECORD_LOCK  0x53554204U
#define SUCRUNE_BROKER_RECORD_CLOSE 0x53554205U
/* Release an internal handle without a logical guest close on this inode. */
#define SUCRUNE_BROKER_PRIVATE_CLOSE 0x53554206U
/* Actual file/directory durability operations. args={opaque_handle,0,0,0},
 * no payload. Broker completion remains pending until the host call returns. */
#define SUCRUNE_BROKER_FSYNC 82U
#define SUCRUNE_BROKER_FDATASYNC 83U
/* Query protocol: access (48/439) args={dir_handle_or_AT_FDCWD, mode,
 * flags, 0}; readlink (78) args={dir_handle_or_AT_FDCWD, capacity, 0, 0}.
 * Payload is one NUL-terminated project path. Absolute paths ignore dirfd.
 * Access checks use the manager's project-file authority and preserve kernel
 * DAC/ACL checks through a pinned FD. AT_EMPTY_PATH is supported; queries
 * require equal real/effective IDs (as in Android apps). Merge symlink targets into the guest path, up to 40 expansions.
 * readlink and AT_SYMLINK_NOFOLLOW address the final link itself.
 * /proc/self/exe must be virtualized by the guest runtime, never this broker. */
#define SUCRUNE_BROKER_FACCESSAT 48U
#define SUCRUNE_BROKER_FACCESSAT2 439U
#define SUCRUNE_BROKER_READLINKAT 78U
/* linkat: args={old_dir_handle,new_dir_handle,flags,0}; exactly two NUL-
 * terminated project paths. Absolute paths ignore their corresponding dirfd.
 * AT_SYMLINK_FOLLOW resolves the source to its guest target.
 * AT_EMPTY_PATH on a borrowed file is subject to the kernel's actual authority. */
#define SUCRUNE_BROKER_LINKAT 37U
/* args={dir_handle, flags, has_times, 0}. Payload is path + NUL, followed
 * when requested by two AArch64 timespecs (signed 64-bit seconds/nanoseconds).
 * The Linux NULL-path file-descriptor operation is normalized to AT_EMPTY_PATH. */
#define SUCRUNE_BROKER_UTIMENSAT 88U
/* The mask belongs to one broker session, is copied on fork and survives exec.
 * Guest openat/mkdirat set args[3] to 1 and args[2] to the requested mode.
 * Older callers omit the mode and retain owner-only creation defaults. */
#define SUCRUNE_BROKER_UMASK 166U
/* ftruncate (46): args={file_handle, signed_length, 0, 0}; never a host fd
 * or a path. fallocate (47) accepts {writable_handle, 0, offset, length}.
 * Both bound the resulting extent, including sparse extensions. */
#define SUCRUNE_TRUNCATE_LIMIT INT64_C(268435456)
/* fchmodat (53): args={dir_handle, mode & 0777, 0, 0}, one NUL-terminated
 * path. Resolve and pin the target under the same project transaction. */
/* fchmod (52): args={opaque_handle, mode & 0777, 0, 0}, no payload.
 * Reject set-ID/sticky/type bits; only broker-owned regular/directory FDs. */
/* Broker handles are opaque resources, not guest FD numbers. The worker owns
 * the 0..63 guest table and can map closed standard slots to these handles. */
/* openat accepts O_NONBLOCK on the supported regular files/directories. Its
 * guest-visible value belongs to the opaque open description (shared by guest
 * dup aliases), and F_SETFL may change O_APPEND/O_NONBLOCK. The manager always
 * retains its own O_NONBLOCK safeguard; F_GETFL hides that internal bit unless
 * the guest requested it. FIFO/device/socket files remain rejected. */
/* Private broker protocol operation, not a forwarded Linux syscall. Commit it
 * only after a replacement image is ready. No arguments or payload are valid. */
#define SUCRUNE_BROKER_EXEC_COMMIT 0x53550001U
/* Fork a per-process broker session. Empty request with zero arguments. A
 * successful empty reply has result=0 and exactly one connected AF_UNIX
 * SOCK_SEQPACKET right. Child cwd/descriptor flags are copied. Its file slots
 * reference the same open file descriptions. All sessions retain completion. */
#define SUCRUNE_BROKER_FORK_SESSION 0x53550002U
/* Borrow the original O_RDONLY/O_RDWR regular file for a non-executable
 * MAP_SHARED. args={handle,write_requested,0,0}, no payload. Success returns
 * one CLOEXEC right. The runner closes it immediately after mmap. */
#define SUCRUNE_BROKER_MAP_FILE 0x53550003U
/* Linux openat with an optional direct read FD. Arguments and slot result
 * match openat; the request must specify O_RDONLY without O_PATH. The
 * manager may attach the same open description for a regular file. The
 * broker slot stays live even if no FD reaches the receiver. */
#define SUCRUNE_BROKER_OPEN_READ 0x53550004U
/* Filesystem Landlock ABI 3: 444 {handled_fs,size,flags,0};
 * 445 {ruleset,type,allowed_fs,parent_file}; 446 {ruleset,flags,0,0}.
 * Opaque rulesets share the regular handle allocator and default to CLOEXEC.
 * 167 carries PR_SET/GET_NO_NEW_PRIVS. Policy and NNP survive fork and exec. */
#define SUCRUNE_BROKER_LL_SPECIAL 0x53550005U
/* Loader-only O_RDONLY snapshot. args[3]=1 requests an optional direct read
 * right; args[3]=0 leaves all reads in the broker. Requires READ_FILE and EXECUTE. */
#define SUCRUNE_BROKER_OPEN_EXEC 0x53550006U
struct sucrune_request {
    uint32_t magic, operation;
    int64_t args[4];
    uint32_t size, reserved;
    unsigned char data[SUCRUNE_IO_LIMIT];
};
struct sucrune_response {
    uint32_t magic, size;
    int64_t result;
    unsigned char data[SUCRUNE_IO_LIMIT];
};
/* Manager only. Returns an owned SOCK_SEQPACKET client FD, or -errno.
 * Closing every copy of the client releases the broker and all its files. */
/* completion receives an owned pipe read FD. Its EOF proves all file operations
 * and descriptor cleanup finished; wait for it before releasing the environment. */
int sucrune_workspace_broker(const char *workspace, int *completion);
/* Explicit network capability, independent of project path authority. The old
 * constructor remains network-disabled. policy constants: network_broker.h. */
int sucrune_workspace_broker_with_network(const char *workspace, int *completion, int network_policy);
/* Explicit network snapshot for OUTBOUND. Zero uses Android's process/default
 * network. DNS and external TCP both use this handle; never binds the process.
 * Original entry points remain compatible; neither enables networking by default. */
int sucrune_workspace_broker_with_network_handle(const char *workspace, int *completion,
    int network_policy, uint64_t network_handle);
int sucrune_workspace_broker_profile(const char *workspace, int *completion, int network_policy,
                                     uint64_t network_handle, enum sucrune_workspace_profile profile);
struct sucrune_exec_image;
struct sucrune_guest_directory;
/* Mount at /workspace in the Linux profiles. Consumes the callback context on
 * every return path, including failure. The caller retains ownership of image. */
int sucrune_workspace_broker_mounted(const char *workspace, int *completion, int network_policy,
                                    uint64_t network_handle, enum sucrune_workspace_profile profile,
                                    enum sucrune_write_scope scope, struct sucrune_exec_image *image,
                                    const struct sucrune_guest_directory *mount);
int sucrune_workspace_broker_with_image(const char *workspace, int *completion, int network_policy,
                                    uint64_t network_handle, enum sucrune_workspace_profile profile,
                                    enum sucrune_write_scope scope, struct sucrune_exec_image *image);
int sucrune_workspace_broker_scoped(const char *workspace, int *completion, int network_policy,
                                    uint64_t network_handle, enum sucrune_workspace_profile profile,
                                    enum sucrune_write_scope scope);
#endif
