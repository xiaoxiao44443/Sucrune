# Linux DNS and HTTPS on Android

Status: design for the original ARM64 Linux Node **v24.22.2**. The independent
proxy now has eight query slots, four workers, eight TCP clients and 64 registered
source tokens. Its portable codec passed 3/3 on Windows; a standalone Android 15
shell-UID run passed 9/9 with an injected raw resolver and real loopback sockets.
See the Android result and its log digest in [the execution validation report](validation/android15-agent-execution-progress.json). Neither
test exercises Android's resolver or UDP permissions in the isolated native
runner. The remaining design is not a claim of working guest DNS or HTTPS.

## Preserve the two Linux resolver paths

`dns.lookup()` calls the operating-system resolver through libuv's worker pool.
`dns.resolve*()` uses DNS protocol queries through c-ares and does not use the
hosts file. Replacing an application lookup callback would exercise a different
path from unmodified Node. `getaddrinfo()` is a libc function, not an interceptable
Linux syscall. The guest calls its own glibc, not Android Bionic.
[Node v24.22.2 DNS documentation](https://github.com/nodejs/node/blob/v24.22.2/doc/api/dns.md),
[libuv getaddrinfo implementation](https://github.com/libuv/libuv/blob/v1.52.1/src/unix/getaddrinfo.c).

The prepared rootfs pins Debian `libc6_2.36-9+deb12u14_arm64.deb`. Node's pinned
headers identify libuv **1.52.1** and c-ares **1.34.9**. The c-ares sources cited
below are that matching upstream release; they are not evidence that every
vendored file is byte-identical.
[libuv version](https://github.com/nodejs/node/blob/v24.22.2/deps/uv/include/uv/version.h),
[c-ares version](https://github.com/nodejs/node/blob/v24.22.2/deps/cares/include/ares_version.h).

Node's default `net` lookup adds `AI_ADDRCONFIG` when applicable. glibc probes
interfaces with NETLINK_ROUTE and also probes candidate source addresses with
UDP connect/getsockname while sorting results. Its interface probe falls back to
considering both IPv4 and IPv6 when discovery fails. Therefore a first version
can explicitly reject unsupported netlink and verify this real fallback; it
must not manufacture successful interface enumeration.
[Node net.js](https://github.com/nodejs/node/blob/v24.22.2/lib/net.js),
[glibc getaddrinfo](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/posix/getaddrinfo.c),
[glibc interface discovery](https://github.com/bminor/glibc/blob/glibc-2.36/sysdeps/unix/sysv/linux/check_pf.c).

glibc's DNS implementation creates nonblocking UDP sockets, connects to the
resolver, polls, and can batch A/AAAA queries with `sendmmsg`. Its TCP fallback
uses a stream socket without SOCK_NONBLOCK and two-byte DNS framing. Consequently
the current TCP-only, nonblocking-only contract is insufficient even if one A
lookup happens to pass. c-ares reads Linux resolver configuration in this Linux
build and switches to TCP for truncated UDP replies.
[glibc DNS transport](https://github.com/bminor/glibc/blob/glibc-2.36/resolv/res_send.c),
[c-ares configuration](https://github.com/c-ares/c-ares/blob/v1.34.9/src/lib/ares_sysconfig_files.c),
[c-ares transport](https://github.com/c-ares/c-ares/blob/v1.34.9/src/lib/ares_socket.c),
[c-ares truncation handling](https://github.com/c-ares/c-ares/blob/v1.34.9/src/lib/ares_process.c).

c-ares opens a plain SOCK_DGRAM/STREAM before its default socket callback sets
nonblocking mode and close-on-exec. Node installs a socket-state callback for
libuv polling, not a replacement socket constructor. The current UDP constructor
therefore accepts plain SOCK_DGRAM as well as SOCK_NONBLOCK while retaining a
physically nonblocking transferred FD. The guest must see its own F_GETFL state
and be able to enable O_NONBLOCK before data I/O. This constructor support does
not implement blocking I/O or glibc's blocking DNS-over-TCP fallback.
[c-ares connection creation](https://github.com/c-ares/c-ares/blob/v1.34.9/src/lib/ares_conn.c),
[matching Debian c-ares source](https://sources.debian.org/src/c-ares/1.34.9-1/src/lib/ares_set_socket_functions.c/),
[Node ChannelWrap setup](https://github.com/nodejs/node/blob/v24.22.2/src/cares_wrap.cc).

## Android resolver is the upstream

The normal manager requires INTERNET and ACCESS_NETWORK_STATE, both normal
permissions rather than root access or a runtime permission dialog. The
isolated UID's permissions are different; passing a socket does not establish
permission to create, bind or perform every operation on it.
[Android connectivity permissions](https://developer.android.com/develop/connectivity/network-ops/connecting).

ConnectivityManager supplies the selected Network and LinkProperties, including
DNS servers, search domains and Private DNS state. DNS server IPs alone are not
a complete resolver configuration: Android directs applications to use encrypted
DNS when Private DNS is active, and its system resolver already implements the
required validation. Direct UDP to those IPs can bypass that behavior and can
mis-handle VPN or network-specific routing. Do not use a hardcoded public
resolver as an automatic fallback.
[LinkProperties](https://developer.android.com/reference/android/net/LinkProperties),
[network state and callbacks](https://developer.android.com/develop/connectivity/network-ops/reading-network-state).

Use API 29 `android_res_nsend(network, wire_query, length, flags)` with ordinary
flags. It returns a query FD or a negative POSIX error. `android_res_nresult`
returns a raw response or negative error and **consumes/closes the FD**, including
failure. `android_res_cancel` cancels a pending query. The network handle can
also select each outbound socket with `android_setsocknetwork` before connect;
avoid process-wide binding because projects execute concurrently.
[NDK networking API](https://developer.android.com/ndk/reference/group/networking).

An alternative public API is `DnsResolver.rawQuery(Network, byte[], ..., Callback)`
with CancellationSignal. It also returns real DNS wire data and follows the
Android resolver path. A Bionic address-only getaddrinfo RPC is not a substitute:
it loses generic DNS answers and still requires a Linux NSS adapter or application
changes, and would not cover c-ares.
[Android DnsResolver](https://developer.android.com/reference/android/net/DnsResolver).

Snapshot the selected Network handle for each execution or explicitly version
network changes. DNS and outbound sockets must use the same selection. A lost
Network should cause a reported failure/retry decision, not an invisible escape
from the user's VPN. NETWORK_UNSPECIFIED may deliberately mean Android's default
network; record that choice without pretending it pins a route.

## Proposed per-execution DNS proxy

Expose the virtual resolver **127.0.0.53:53** in the guest. A manager-owned proxy
binds UDP and TCP to the same ephemeral **127.0.0.1** port. No privileged bind,
root or DNS server installation is needed. This is a local transport adapter;
answers come from Android's resolver, not a generated hostname/IP table.

Rootfs preparation supplies `/etc/nsswitch.conf` with `hosts: files dns` and a
project-managed `/etc/resolv.conf` naming the virtual resolver. A hosts file may
describe localhost honestly. Search domains must be explicitly copied from the
selected network or configured per project. These files and a fixed network
policy are execution configuration, not authorization derived from mutable guest
environment text. Existing guest NSS/NSCD probes must fail explicitly when
unsupported rather than access Android paths.

The network broker records the DNS route in typed, generation-checked resource
metadata. Connect/sendto to the virtual address maps to the proxy endpoint;
getpeername and recvfrom/recvmsg source addresses map back to the virtual address.
Do not expose the manager's ephemeral proxy port through a query or error
payload. Register the source port of each canonical client socket before it can
submit queries. Remove registration only after the last alias/resource releases.
The proxy must reject unregistered clients: device loopback is shared with other
applications and projects, not a private network namespace.

The proxy preserves actual DNS packets, query IDs, questions, response codes,
CNAMEs, TTLs and additional records. Validate lengths and correlation before
delivery. NXDOMAIN and NODATA are different; a platform transport error is not a
successful empty address list. Bounded local errors may produce a matching
SERVFAIL response, but never fabricated A/AAAA success. Do not log domain names
or DNS payloads by default. Unsupported query forms fail explicitly.

Suggested initial bounds are 32 admitted queries, four resolver workers, eight
TCP clients, a 1 MiB aggregate buffer budget, bounded query size and at most
65535-byte DNS responses. These are proposed limits, not implemented values.
TCP needs two-byte framing, partial reads/writes and connection-generation
checks. UDP sends remain one atomic datagram. Oversized responses require a
valid TC response with a supported TCP retry path; never split them into the
file broker's 4096-byte records.

## Resolver ownership and cancellation

The DNS IO thread and a fixed worker pool are independent of the serial file
broker. Neither query submission nor result collection runs while holding its
transaction lock or the guest state lock.

Each query has one owner and a generation: queued, submitting, pending,
collecting, completed/cancelled. The owner removes the query from its readiness
set before consuming the FD. Only pending queries use `android_res_cancel`.
Collection consumes the original FD exactly once; no unconditional close follows
it. During collection, cancellation may shutdown a separately retained alias to
wake the collector, but must never close an integer FD that the collector may
already have consumed and another thread may have reused.

This distinction is required by the inspected AOSP implementation: result
collection reads framing and payload from a stream, owns the FD with RAII, and
cancellation closes it. Initial readability is not proof that every payload byte
has arrived. Submission itself performs local netd IPC. Setting O_NONBLOCK and
calling the all-or-nothing result API could discard a partial valid response.
The source reviewed was NetdClient.cpp blob
`a33c6805660531318ecd0ca685b36ebd82b0894b`; it explains ownership, not a universal
Android/vendor latency guarantee.
[AOSP NetdClient.cpp](https://android.googlesource.com/platform/system/netd/+/refs/heads/main/client/NetdClient.cpp).

Shutdown stops admissions, closes listening sockets, cancels queued/pending
work, wakes active collection, and joins all workers before freeing state or
closing the broker completion barrier. A join timeout must retain owned state and
report incomplete cleanup. Detaching a worker and freeing its buffers is invalid.
There is no public hard-timeout contract for the submission IPC. If a strict
deadline must cover an unresponsive Android system resolver too, move the
resolver into a disposable ordinary-App-UID process with kill/wait supervision;
a manager thread alone cannot honestly provide that guarantee. This remains an
integration decision and a fault-injection acceptance gate.

Proposed independent native interface, before production wiring:

```c
struct sucrune_dns_proxy;
int sucrune_dns_proxy_start(const struct sucrune_dns_config *,
    const struct sucrune_dns_backend *, struct sucrune_dns_proxy **);
int sucrune_dns_proxy_endpoint(struct sucrune_dns_proxy *, uint16_t *port);
int sucrune_dns_proxy_allow_client(struct sucrune_dns_proxy *,
    int transport, int canonical_fd, uint64_t resource_token);
int sucrune_dns_proxy_remove_client(struct sucrune_dns_proxy *, uint64_t token);
void sucrune_dns_proxy_request_stop(struct sucrune_dns_proxy *);
int sucrune_dns_proxy_join(struct sucrune_dns_proxy *, int timeout_ms,
    struct sucrune_dns_stats *);
int sucrune_dns_proxy_destroy(struct sucrune_dns_proxy *); /* only after join */
```

The injected backend supplies submit, consume-result and consume-cancel
operations. This permits deterministic tests without public DNS. Callback return
values are negative errno, not a mixture of -1/errno and resolver EAI codes.
Only new `dns_proxy.c/h` and its own tests are in scope initially; current network
modules remain frozen until their application validation completes.

## Guest socket changes needed separately

| ARM64 interface | Required behavior |
| --- | --- |
| socket 198 | INET/INET6 DGRAM as well as STREAM; retain physical nonblocking mode independently of guest flags |
| connect 203 | UDP peer assignment, explicit AF_UNSPEC disconnect where supported, virtual DNS route metadata |
| sendto 206 / recvfrom 207 | Datagram atomicity, zero-length datagrams, source length/truncation, retained open description |
| sendmsg 211 / recvmsg 212 | Bounded iovecs and ARM64 msghdr normalization; packet flags and source copyout |
| sendmmsg 269 | Real per-message accounting and partial batch result; glibc paired A/AAAA path |
| poll/ppoll, epoll, FIONREAD | Readiness and byte counts on transferred UDP descriptors, verified in the native runner |
| logical blocking TCP | Deadline-aware connect/read/write for glibc DNS TCP fallback without holding guest state lock |

Do not infer packet EOF from a zero return. MSG_TRUNC must preserve Linux's
full-datagram length semantics. Pin one open description for an entire vectored
operation; never resolve a recycled guest FD between iovecs. Validate guest
sockaddr, msghdr/mmsghdr layouts and all pointer arithmetic independently of host
ABI. Guest ancillary SCM_RIGHTS is unrelated to private broker SCM_RIGHTS and
must remain unsupported until explicitly designed. Additional calls such as
recvmmsg should be admitted from traces and actual tests, not claimed preemptively.

First measure manager-created UDP transferred by **the real SCM_RIGHTS channel**
into **the native isolated runner**: connected and unconnected send/receive,
sendmsg/recvmsg, epoll, getsockname/getpeername, options, cancellation and FD
cleanup. Binder TCP evidence cannot answer these questions. If Android policy
denies the data path, an AF_UNIX-backed DNS socket adapter is a separate fallback
with explicit virtual type/address/readiness semantics, not proof of general UDP.

## Outbound TCP and TLS

The reserved OUTBOUND policy currently returns EOPNOTSUPP. Enabling DNS does not
enable it implicitly. Add explicit outbound connection authorization and selected
Network binding without also enabling external listeners, multicast or arbitrary
binds. Loopback remains shared and file-path containment is a separate concern.

TLS stays inside original Linux Node/OpenSSL over the transferred TCP socket.
The manager does not terminate TLS or manufacture certificate success. Official
Node includes bundled Mozilla roots; CLI selection is build-dependent. Verify
the imported binary's root counts and options, and use `--use-bundled-ca` explicitly
for the first controlled test. Linux `--use-system-ca` concerns the Linux/OpenSSL
trust locations, not Android Java TrustManager automatically. Extra PEM roots
are explicit startup configuration through NODE_EXTRA_CA_CERTS; a caller's
explicit `ca` changes the trust selection.
[Node v24.22.2 CLI trust options](https://github.com/nodejs/node/blob/v24.22.2/doc/api/cli.md),
[Node v24.22.2 TLS certificates](https://github.com/nodejs/node/blob/v24.22.2/doc/api/tls.md).

## Acceptance sequence

1. Finish actual TCP/HTTP loopback validation, then the native-runner UDP/SCM
   capability matrix. Keep denied operations distinct from unattempted ones.
2. Test the proxy with a deterministic raw backend: A/AAAA, NXDOMAIN, NODATA,
   CNAME, duplicate IDs across clients, partial TCP frames, TC/retry, oversized or
   malformed packets, queue exhaustion, source registration and stale generations.
3. Inject late/partial resolver replies, cancellation during each ownership state,
   deadline expiry and network loss. Require actual joins, zero pending queries,
   listener closure and the existing four cleanup barriers before environment reuse.
4. Run unmodified Node `dns.lookup`, `dns.resolve4/6` and concurrent fs/resolver
   workers using the generated Linux configuration. Record unsupported probes
   and verify fallback rather than changing the Node application to bypass it.
5. Test local TLS with an explicit test CA: correct name succeeds; wrong name and
   untrusted CA fail. Then perform a credential-free public HTTPS GET using real
   DNS and certificate verification. No TLS verification bypass or IP substitution.
6. Only after these pass, run DSH's separately authorized external Agent workflow.
   Resolver/TLS tests do not consume or persist model credentials.
