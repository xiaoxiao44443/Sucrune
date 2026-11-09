# Original SDK protocol validation

Status: **the original SDK initialize/shutdown exchange passed on Android 15**,
with explicit foreground validation. The final expanded Linux/Node/DSH suite
finished **36/36**, and the same unchanged APK pair passed three bundled-backend
regression groups (**12 + 11 + 10**), for **69/69** final app cases. The prior
34/36 run's idle cancel/timeout expectation failures remain recorded; corrected
shutdown boundaries and synchronous cancellation publication passed the final
rerun. This is not a general Agent or full Linux compatibility claim.

The completed `linux-dsh-interactive-final.txt` log has SHA256
`D1C42DBD7EE93F658FE07AD3B34510066347F1E6C68916A29E7FAA35554C398A`.
The test kept stdin open, validated initialize ID 1 and the server identity below,
then sent shutdown ID 2 and validated its empty result. It observed **206 input
bytes, zero notifications, exit 0 and all four cleanup barriers**. These were
original Linux Node/DSH processes in the non-debuggable isolated Android worker,
not host-side or desktop Harness execution. The separate SDK EOF/profile-activation
checks also passed and were not weakened to obtain the protocol result.
No prompt/model/tool request, Web service, mobile npm installation or
external-network workflow was exercised. The earlier handshake pass in
`linux-dsh-interactive-queries.txt`, its two failed cases and all intervening
history remain in [device evidence](validation/android15-linux-progress.json).
The reviewed packages are original published `@deepseek-ai/*@0.2.2-rc.1` artifacts
from the SHA-verified SDK-minimal fixture. The lock/provenance and full package
selection are recorded in [`dsh-sdk-minimal-validation.json`](dsh-sdk-minimal-validation.json).
Primary provenance is the [official package manifest](https://registry.npmjs.org/@deepseek-ai/dsh/0.2.2-rc.1)
and [pinned source commit](https://github.com/deepseek-ai/deepseek-harness/tree/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159).
The published `lib/index.js` files, rather than a current moving branch, were
read for the observations below.

## Legitimate minimal exchange

Run the unchanged entrypoint
`/opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js sdk-minimal`, with the existing
isolated HOME/DSH_HOME/cache/cwd configuration and no model credentials. Each
frame is UTF-8 JSON followed by LF:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"cwd":"/workspace/dsh-test-work","provider":"deepseek-official","model":"deepseek-flash"}}
```

Keep stdin open. Wait for a complete response with exactly the matching ID,
`jsonrpc: "2.0"`, no `error`, and
`result.serverInfo.name == "deepseek-harness-sdk-runtime"`,
`result.serverInfo.version == "0.0.1"`. Only then send:

```json
{"jsonrpc":"2.0","id":2,"method":"shutdown","params":{}}
```

Require its matching response with `result: {}` and no error. The server's
shutdown handler schedules output flush, root disposal and exit 0. Await the
actual execution result and existing cleanup barriers; acceptance is not merely
receipt of the shutdown JSON. Close any remaining input through the manager
after the protocol has finished, and cancel/wait on any failure or deadline.
Use a bounded line parser, total output budget and original absolute execution
deadline. Do not add fixed sleeps as a substitute for responses.

No `tools/list` or `session/list` method is present in this version's dispatch
switch. `session/working-directory/get` calls `getOrCreateSession`; it is not a
side-effect-free metadata listing and is unnecessary for this test. Do not send
`session/prompt`, `session/query`, resume, working-directory mutation or tools.

## Why prequeued finite input is not a reliable test

The source does not guarantee a failed exchange on every finite-input run, but
it does expose independent shutdown races:

| Published source | Relevant behavior |
| --- | --- |
| `dsh-sdk-protocol/lib/index.js:162` (`drainLines`) | Invokes async `handleLine` without awaiting it. Two lines are dispatched concurrently; their order in a single byte buffer is not a response barrier. |
| `dsh-sdk-jsonrpc-server/lib/index.js:840` | The initialize request first awaits loader settlement, then awaits `server.handleRequest`. |
| `dsh-sdk-jsonrpc-server/lib/index.js:467` | `initialize` may await adapter mounting and always awaits `resolveCallConfig` before marking initialized or returning identity. |
| `dsh-sdk-jsonrpc-server/lib/index.js:667` | `shutdown` begins server disposal immediately; it does not wait for an outstanding initialize request. |
| `dsh-sdk-app/lib/index.js:39` and `dsh-cmdline/lib/index.js:50` | EOF schedules `appExit(0)` after `appReady`. This is not an incoming-request completion or response-flush barrier. |
| `dsh-sdk-protocol/lib/index.js:175` | Input-end drains complete lines and rejects pending outbound requests; it does not join outstanding inbound request handlers. |

Prequeueing initialize and shutdown can therefore dispose the server while
initialize is awaiting work. Sending initialize alone and closing stdin can
request app shutdown before its response is delivered. Neither result should be
misclassified as Linux syscall incompatibility. Keep the finite-input API and
EOF regression intact; use a distinct interactive input lifetime for this test.

## No-model and no-network reasoning

`initialize` configures a route and validates model capabilities. It is not a
generation request, but its metadata path is asynchronous and must still be
reviewed for network side effects:

- `dsh-llm/lib/index.js:2179` resolves call configuration through model metadata.
- `dsh-llm-deepseek-api-key/lib/index.js:65` converts only a missing-credential
  result to `undefined`; unexpected credential errors still propagate.
- That adapter's model-listing cache has a fetch loader, but
  `dsh-llm-deepseek/lib/index.js:2553` starts it only when a credential is present.
  With no credential, it returns its local view/catalog.
- The initialize handler returns server identity without creating an Agent or
  calling prompt/query. Shutdown releases server-owned state.

This supports a no-model handshake using a fresh fixture environment without
credentials. It is not a promise that initialize can never perform network I/O
under other configuration: credentials and a changed adapter/catalog can cause
a model-listing refresh. Do not supply account data or import a real user HOME
for this check.

## Manager input requirements

`RuntimeClient` now provides a distinct `executePathInteractive` entry point,
whole-block `writeInput` admission and explicit `closeInput`. It owns a socketpair
writer in a dedicated feeder and drains stdout/stderr independently. The FD
transfer ABI is unchanged, but real Node stdin recognition also required guest
`getsockname`/`getpeername` and bounded `getsockopt` queries on existing local FDs.
Named UNIX addresses remain rejected; this does not enable guest socket creation,
connect/listen or general Linux networking. Go stores request/result as JSON
objects, so it does not require a persistence schema migration for an explicit
interactive mode. Recovery still marks unfinished executions lost, with no
input replay or stream resumption.

The manager input lifetime uses whole-chunk copied admission with a
cumulative 1 MiB limit, explicit EOF, one descriptor-owning feeder, and bounded
waits that observe peer closure, cancellation, timeout and execution completion.
Accepted byte counts are not guest-consumption acknowledgments. Finalization
must retain feeder completion as a cleanup barrier, including startup failure.
Input contents must not be recorded in execution events or durable metadata.

Compilation, queue/state checks and device execution remain separate evidence
layers. [The compiler record](validation/dsh-interactive-compile.json) only proves
compilation; the device log above establishes this specific protocol exchange.
The final rebuilt device run passed the cancel/write publication revision and
corrected shutdown-output checks, including an empty open stdin queue, deadline,
guest-close detection, cleanup barriers and project reuse. The final diagnostics
reported no remaining projects or import staging files; this observation is not
an additional functional test. Foreground success does not establish background
scheduling reliability or explain the earlier scheduling pause.
