# Linux TCP broker proposal

Status: **proposal, not implemented**. The target is original Linux ARM64 Node
`net`/`http` clients and local servers using numeric loopback addresses. DNS, UDP,
external endpoints, TLS policy and network namespaces are outside the first
implementation. This document does not claim that passing an FD grants every
socket operation to an Android isolated UID.

## Measured capability and remaining gate

The corrected probe completed **5/5 measurement cases** on the connected
Android 15 device. Its ordinary manager UID was 10422; the disposable Service
UIDs were different isolated UIDs. These are capability measurements, not five
successful isolated networking features. The detailed evidence is retained in
[`validation/android15-network-capability.json`](validation/android15-network-capability.json).

| Operation in the isolated Service | Observed result on this device |
| --- | --- |
| Create IPv4/IPv6 TCP sockets directly | Both rejected with EACCES |
| Read/write an already connected socket received from the manager | Independent PING/PONG verification and epoll succeeded |
| Connect a received unconnected socket | EINPROGRESS, successful completion, then verified PING/PONG; manager fallback was not needed |
| Listen/accept on a received listener | Both rejected with EACCES; manager operations on the same socket description and manager echo succeeded |
| Nonblocking flags, SO_ERROR, selected options and FIONBIO | Succeeded; FIONREAD on the listener returned EINVAL in both processes |

The transfer used **Binder ParcelFileDescriptor**, not SCM_RIGHTS on the runtime
broker channel. Service death and FD cleanup were confirmed. The probe has no
forked native runner, so its Binder death does not establish runner death. The
actual Linux runner, SCM_RIGHTS framing/cleanup, guest syscalls, original Node
networking and other Android/vendor policies remain untested. The initial 0/5
run was an IPv4-mapped IPv6 loopback-validation defect in the probe, subsequently
fixed and separately covered by host address tests; it was not a permission
finding.

**Design inference:** manager creation plus local isolated data/readiness is a
promising path on this device. Manager listen/accept is necessary here. Although
local connect succeeded, the proposal keeps manager connect as an available
control path for policy and compatibility; that choice is not a claim that this
device denied local connect. Fresh-runner and explicit SCM_RIGHTS tests still
gate implementation acceptance.

## Existing implementation and smallest useful change

`native/workspace_broker.h` defines a SOCK_SEQPACKET request/response protocol:
one operation, four signed 64-bit arguments, and at most 4096 payload bytes.
The worker's `shell_runtime.c:exchange` sends bytes with sendto and receives
bytes with recvfrom. The manager's `workspace_broker.c:serve` has one serial
receive/dispatch/send loop. Neither side currently receives ancillary FDs.
The manager holds 64 file resources in an opaque handle table, a project root
FD and cwd. The completion pipe closes only after operations and resources are
finished. Guest FD numbers belong to the separate 64-entry worker table.

Use that existing per-execution control channel for new **private network
operations**, while transferring actual socket aliases to the worker with
SCM_RIGHTS. Keep a canonical socket and opaque token in the manager. The worker
uses its local alias for data/readiness and the token for authorized management
operations. Guest memory receives only guest FD numbers, normalized addresses
and option values, never a host descriptor or manager token.

The first version need not add an asynchronous broker event protocol:

- All manager sockets are physically `SOCK_NONBLOCK | SOCK_CLOEXEC`.
- `connect` returns its immediate 0 / EINPROGRESS / other errno. The manager
  does not wait for connection completion.
- `accept4` returns a connection or EAGAIN immediately. The manager does not
  accept proactively or wait for clients inside the broker loop.
- The worker's alias refers to the same kernel socket. Its existing local epoll
  path can observe connection completion and listener readability, subject to
  measured isolated-domain permissions.
- The guest then consumes `SO_ERROR`. The manager must not poll and read it
  early: reading SO_ERROR clears the pending socket error for all aliases.

This preserves Node's real nonblocking flow while avoiding network waits inside
the file broker. If transferred sockets cannot be read/written or registered in
epoll by the actual runner, this data path is unavailable. A manager byte pump
over AF_UNIX would be a different proxy design with additional readiness,
half-close, error and buffering semantics; it is not a small reuse of file RPC.

## Node/libuv path to cover first

The pinned Node v24.22.2 libuv source provides a concrete initial target.
[core.c](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/src/unix/core.c)
creates sockets with NONBLOCK/CLOEXEC and uses Linux accept4. Its socket fallback
does not turn a permission error into a successful alternative.
[tcp.c](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/src/unix/tcp.c)
handles connect/bind/listen and socket options.
[stream.c](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/src/unix/stream.c)
uses SO_ERROR on connection completion, ordinary read/write/writev for TCP data,
and shutdown(SHUT_WR) when finishing the write side.

| Linux ARM64 interface | Proposed handling |
| --- | --- |
| socket 198 | Manager creates validated INET/INET6 TCP socket and returns one FD plus token |
| bind 200, listen 201 | Manager operates on its canonical socket under project endpoint policy |
| connect 203 | Manager starts nonblocking connect; immediate errno returned unchanged |
| accept4 242 | Manager performs one nonblocking accept and returns one new FD/token and normalized peer address |
| getsockname 204, getpeername 205 | Normalize local query if permitted, otherwise manager query |
| setsockopt 208, getsockopt 209 | Whitelisted integer options through one chosen local or manager path |
| shutdown 210 | Explicit SHUT_RD/WR/RDWR operation; manager delegation is a conservative first route |
| read/write/readv/writev | Worker-local retained socket alias; preserve short I/O and EAGAIN |
| epoll/poll | Existing stable-alias/retained-wait callbacks, after actual permission verification |
| fcntl / FIONBIO / FIONREAD | Separate kernel nonblocking safeguards from guest flags; delegate unavailable operations explicitly |

`guest_sockets.c/h` currently provides sockaddr codecs, AF_UNIX socketpair and a
bounded integer getsockopt helper. It does **not** implement this IP broker or
establish Node networking. Use its normalized address handling rather than copying
host sockaddr structs directly into ARM64 guest memory.

## Control messages and SCM_RIGHTS admission

Reserve symbolic private opcodes such as `NET_SOCKET`, `NET_BIND`, `NET_CONNECT`,
`NET_LISTEN`, `NET_ACCEPT`, `NET_NAME`, `NET_GETOPT`, `NET_SETOPT`, `NET_SHUTDOWN`
and `NET_RELEASE`. Do not overload file-open/read operations or forward arbitrary
syscall numbers. The existing private exec-commit opcode already demonstrates
the distinction. Exact numeric allocation is an implementation step.

Keep existing file packets compatible but introduce a versioned network payload.
Define fixed-width serialized fields explicitly: token/generation, family/type,
flags, normalized address length and option values. Do not serialize C padding,
size_t, native sockaddr storage or guest pointers. Existing 4096-byte packets are
ample for control metadata; socket addresses remain bounded by the codec's
128-byte limit. The reply must state whether exactly one FD is expected.

`NET_SOCKET` and successful `NET_ACCEPT` return a positive opaque token and exactly
one `SOL_SOCKET/SCM_RIGHTS` FD. Other responses carry no descriptors. A negative
result carries neither a token to adopt nor a descriptor. Tokens need an explicit
resource type and generation; stale release/control requests must not act on a
new socket that reused a table slot. File and socket tokens are not interchangeable.

Both ends must move to a shared recvmsg validator, including ordinary file replies:

1. Receive into a bounded payload and aligned ancillary buffer with
   `MSG_CMSG_CLOEXEC`; require exact packet length, magic, supported operation
   payload version, declared payload length and expected descriptor count.
2. Reject MSG_TRUNC, MSG_CTRUNC, malformed ancillary lengths, multiple rights
   groups, wrong count, unexpected control messages and unsolicited descriptors.
   Close every actual received SCM_RIGHTS FD on every rejection path. Never
   interpret arbitrary unknown ancillary bytes as descriptor numbers.
3. Validate admitted descriptors as sockets with the expected type/family using
   supported queries. Do not expose them until guest slot admission succeeds.
   Keep CLOEXEC on every host-side control/canonical/alias FD; guest CLOEXEC is
   separate metadata.
4. Manager request packets normally carry zero FDs. An unexpected request FD must
   be closed and the protocol rejected, not silently discarded by the old recv.
5. A malformed response makes the control channel unusable. Close it and fail the
   execution so manager EOF cleanup releases resources whose token could not be
   safely decoded. Do not guess a token or continue a desynchronized protocol.

For known-valid replies, preflight and reserve the guest slot before the manager
can create/accept a resource. On local alias/admission/copyout failure, close the
received FD and explicitly release the new manager token. If that rollback cannot
complete reliably, poison the channel and use full broker cleanup. Successful
sendmsg means the receiver has an FD reference queued; it does not mean a guest
FD was published. A worker death before admission is handled by channel EOF.

This is an actual sendmsg/recvmsg protocol extension. Successful Binder PFD probes
are useful operation evidence, but do not test SCM_RIGHTS control-message parsing,
truncation behavior or this delivery path. See the Linux
[UNIX socket ancillary rules](https://man7.org/linux/man-pages/man7/unix.7.html).

## One resource, two authorities, several references

| Reference | Owner and release rule |
| --- | --- |
| Manager canonical socket | One network resource token; closed by final NET_RELEASE or broker shutdown |
| FD queued by successful SCM_RIGHTS send | Transport/kernel until received; channel teardown must release undelivered references |
| Worker received canonical FD | Network resource, not a guest FD number; closed when that resource is released |
| Per-guest-descriptor host alias | Existing FD-table alias hooks; close on guest close/dup replacement/committed CLOEXEC |
| Temporary retained I/O alias | One in-flight operation; close after the syscall/wait completes, including errors |

A network resource must store **both** its local FD and remote token. Treating it
as `SUCRUNE_FD_LOCAL` would close only the local side and leak the manager's
connection/listener. Treating it as `SUCRUNE_FD_BROKER` gives it no epoll-capable
local alias. Introduce an explicit network resource kind and bounded metadata
record; make its release callback close the local canonical FD and send exactly
one remote release when the last guest alias is gone.

Choose the FD-table representation deliberately. Its current release callback
takes only `(kind, int handle)`. A bounded network sidecar can own the pair and
provide explicit local-FD resolution, or the resource/callback API can carry the
pair directly. Do not quietly store a sidecar index in `handle` while old branches
still treat every non-broker handle as a native FD. Audit read/write/readv/writev,
fstat, ioctl, fcntl, alias creation and final release together.

The existing stable alias per guest FD must remain. Epoll's key combines the FD
number with the underlying open description; replacing it with a fresh temporary
dup for every epoll_ctl breaks dup/mod/del behavior. Keep the existing retained
dup pattern for blocking waits and protect against table close/reuse under the
short state lock. See [epoll descriptor lifetime](https://man7.org/linux/man-pages/man7/epoll.7.html).

The manager canonical is a real hidden reference. If it remains after the last
guest alias closes, TCP EOF, listener port release and epoll removal can all be
delayed. Final guest release must therefore acknowledge manager cleanup, or fail
the execution and await broker cleanup. Intentional temporary I/O pins may outlive
a concurrent guest close, as in Linux; they still need bounded cancellation and
release. Do not call shutdown on every alias close: closing one dup must not
half-close the connection used by another. Explicit guest shutdown affects the
shared socket exactly once with the requested direction.

## Flags, errors, serialization and cancellation

All canonical sockets stay physically nonblocking so the manager can never be
trapped in a guest-requested connect/accept. Guest FD_CLOEXEC belongs to each guest
descriptor; O_NONBLOCK belongs to the shared open description. Initial Node scope
can require nonblocking TCP operations, which matches the pinned libuv path.
Do not silently claim blocking behavior. If later accepting a virtual blocking
socket, emulate its wait outside state/broker locks or return an explicit
unsupported error for that operation until implemented. F_SETFL/FIONBIO must not
clear the manager's safeguard accidentally.

Preserve EINPROGRESS, EALREADY, EAGAIN, ECONNREFUSED and short I/O. SO_ERROR is a
read-and-clear value, not an immutable cached status; choose one route for each
guest read and do not have a background manager poll consume it first. The
existing `guest_sockets` integer option normalization is a starting point, not
authorization for every option. Initially whitelist SO_TYPE/SO_ERROR, name
queries, SO_REUSEADDR, selected buffer/keepalive options, TCP_NODELAY and
IPV6_V6ONLY as needed and measured. Never accept arbitrary ioctl buffers or
privileged/device-routing options.

Retain one complete request/reply transaction at a time on each SOCK_SEQPACKET
channel. The current dispatcher already serializes broker exchanges with shared
state. With strictly nonblocking manager control operations, a first integration
can retain that discipline; it must not add a connect/accept completion wait while
holding the lock. Every true epoll/readiness wait releases the state lock and
uses a retained alias, as the local I/O module does now.

If splitting a dedicated broker mutex from state_lock, migrate all file and
network RPCs to the same transaction owner. Copy guest inputs and reserve/pin
resources under the state lock, then release it before waiting for transport;
revalidate output memory and reservation generations before committing. In-flight
control pins must defer remote final release. Merely unlocking between send and
recv lets another guest thread consume the wrong response. Never wait for the
broker mutex while holding a state lock needed by its current owner.

Use bounded transport waits tied to the original execution deadline/cancellation
signal. Network manager dispatch must never perform DNS or a blocking connect,
accept, send or recv. On cancellation, stop accepting new resource admissions,
discard/close staged received FDs, terminate the runner and let broker EOF close
every canonical socket and pending resource. The existing environment release
barrier must include network cleanup before the completion pipe closes; Binder
death alone does not account for the packaged native child. Keep parent waitpid,
output EOF and finite stdin feeder completion in the existing lifecycle contract.

Retain the 64 guest FD limit and a bounded socket resource quota within the
execution's total budget; do not add an unbounded parallel socket table. Bound
backlog, address/option lengths, pending admissions and transient duplicates.
Manager close paths run even after malformed requests, send failure or worker
death. Report counts for canonical sockets, queued/staged transfers and cleanup
errors rather than labeling the environment idle before they are gone.

## Endpoint policy and acceptance sequence

Start with exact numeric loopback addresses and ephemeral ports. Handle verified
IPv4-mapped IPv6 loopback consistently; the app probe already showed why assuming
Java TCP descriptors always use AF_INET is wrong. Reject wildcard binds,
multicast, unsupported scope IDs and external addresses in the initial policy.
Neither FD brokering nor an isolated UID creates a network namespace. Device
loopback is shared with other apps and projects. A project-owned listener registry
and explicit permitted controller endpoints are needed if cross-project loopback
access must be prohibited; allowing all 127.0.0.1 ports is not project isolation.

Suggested new source boundaries, all still proposals:

- `broker_transport.c/h`: one packet validator/transaction owner and ancillary FD
  admission for existing file and new network replies.
- `broker_network.c/h`: canonical socket/token table, endpoint policy and immediate
  nonblocking control operations inside the manager.
- `guest_network.c/h`: normalized syscall translation, bounded network resource
  pairing, guest alias publication and release.
- Existing `guest_sockets` codecs and `guest_local_io` readiness helpers remain
  focused on their current roles; file-path resolution stays in workspace_broker.

Acceptance should proceed in this order:

1. Corrected ordinary-app/isolated-service localhost probe, then the actual
   packaged native runner using the proposed SCM_RIGHTS path. Preserve permission
   refusals and unattempted operations as distinct results.
2. Adversarial ancillary tests: wrong FD count, truncation, extra control messages,
   malformed lengths, full guest table, failed alias/copyout, EOF after send,
   cancellation and failed release. Prove no manager/worker socket leak.
3. Real guest socketpair/read/write/epoll tests for the existing local foundation;
   real nonblocking TCP connect and accept with refused/timeout/EAGAIN cases,
   SO_ERROR, dup/CLOEXEC and exact half-close/EOF behavior.
4. Original Linux Node `net` client and server, then `http` request/response using
   numeric loopback addresses. Verify streaming/backpressure, keep-alive reuse,
   slow-peer cancellation, concurrent guest threads and per-project port policy.

DNS and external HTTP are later capabilities. A localhost TCP success must not
be reported as DNS, Internet access, complete Node networking or an audited
network isolation boundary.
