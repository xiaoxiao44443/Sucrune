# Original DSH Agent validation plan

Run the opt-in controller on a physical Android 15 phone using the
[device instructions](run-dsh-on-device.md). The first model-enabled attempt
exposed a missing Linux file operation: the SDK uses hard links when publishing
its session. Android rejected native hard links from this ordinary app, so
the project broker now maintains the shared inode. The original Linux Node
filesystem workflow and DSH persistent Bash tool have passed separate offline
device tests. The [authenticated device receipt](validation/android15-dsh-agent-acceptance.json)
records one 63/63 run that covers model generation, tool use, session
recovery and cancellation together.

Target remains original `@deepseek-ai/dsh@0.2.2-rc.1`, GNU/Linux ARM64
Node 24.22.2, and Android 15 non-debuggable isolated native runners. References:
[official published package](https://registry.npmjs.org/@deepseek-ai/dsh/0.2.2-rc.1),
[pinned official source](https://github.com/deepseek-ai/deepseek-harness/tree/fcc0ad462172522aaf5c93a7b2e01f6b9f0b0159),
[fixture provenance](dsh-rootfs-provenance.json), and
[existing SDK fixture](dsh-sdk-minimal-validation.json).

## Existing fixture is sufficient for the selected Agent composition

The original `dsh-sdk-minimal/cordis.patch.yml` already mounts Agent, agent-loop,
the native tool executor, DeepSeek API-key adapter, persistent Bash, local file
service and JSONL session persistence. The verified 212-package closure contains
these packages and their Linux ARM64 native payloads. No preparer change or
additional npm package is currently required for this composition. The two-call
Bash tool check verifies one PTY and Bash PID, a retained working directory and
variable, a file artifact, and the correct nonzero exit status. Actual foreground
process groups are checked [separately](validation/android15-bash-job-control.json).
Earlier native session locking, fsync and loopback TCP/HTTP results are in the
[network evidence](validation/android15-agent-network-progress.json).
Full base/Web profiles remain a separate compatibility target.

The stock profile enables `read_image` but explicitly disables ordinary file
`read`, `write` and `edit`. Use the original launcher's documented invocation
overlay, leaving every published package byte unchanged:

```yaml
- id: tool-fs
  config:
    read: true
    write: true
    edit: true
```

Run `/usr/bin/node /opt/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js
--profile sdk-minimal --patch /workspace/<owned-test>/agent.patch.yml`.
The official CLI parses `--profile` and repeatable `--patch` before forwarding
app arguments. The profile's existing sandbox mode is `danger-full-access`;
the test does not change it or claim that it supplies an additional security
boundary. Sucrune's project boundary must not be described as a successful
Landlock/bwrap probe.

## Exact published protocol

Each request/response is one LF-terminated JSON-RPC 2.0 object. Stdin stays open
until the final shutdown response and process completion.

| Operation | Request and acceptance |
| --- | --- |
| Initialize | `initialize` with `cwd`, `provider`, `model`, bounded positive `maxTokens`, `approvalRequests:true`; identity must be `deepseek-harness-sdk-runtime/0.0.1`. |
| Create and prompt | There is **no `session/create` method**. `session/prompt` with a client-chosen nonempty `sessionId` and `contentBlocks:[{type:"text",text:...}]` creates the session on first use and returns `{messageId}` after queuing a durable identified user message. That receipt is not a model-completion result. |
| Await turn | `session/wait` with the owned `sessionId` waits for idle and managed descendants. Require the emitted `turn/end` reason to be `completed`, matching model/tool events and artifacts; idle alone does not mean success. |
| Resume | A fresh SDK process initializes, then `session/resume` with the same ID restores an existing session and returns `{}`. Missing/unreadable/already-owned sessions fail; it must not create a replacement. |
| Query | `session/query` accepts only `sessionId` and nonempty `contentBlocks`; recognized slash commands use the optional commands service. Plain validation input uses `session/prompt` directly. |
| Shutdown/cancel | `shutdown` aborts the transport lifetime, drains/disposes owned Agents and returns `{}` before flushing/exiting. There is **no per-session cancel RPC** in this version. Manager execution cancellation is a separate runtime action, not an invented SDK method. |
| History | There is **no history/list RPC**. Observe `session.event` and inspect the test-owned JSONL after shutdown, then exercise actual `session/resume`; do not fabricate a history endpoint. |

The server emits `session.event` with `{sessionId,event}` and `session.status`.
Events carry monotonic `seq`, `type`, `time`, `data`. Important evidence is:

- `user/message`: the returned durable `messageId`.
- `assistant/message`: original `source.kind="model"`, provider/model identity,
  nonempty exact provider stream and final content; no interrupted result.
- `tool/call`: `callId`, actual tool `name`, raw JSON `arguments`.
- `tool/result`: `message.toolCallId`, content and `isError`; all calls must pair
  with successful results, not just appear in assistant prose.
- `turn/end`: `data.reason.kind="completed"`; `error`, `blocked`, `aborted`,
  `max-tokens` or an incomplete turn cannot pass.

Published source evidence: `dsh-sdk-jsonrpc-server/lib/index.js` lines 381–391
(approval), 415–437 (notifications), 467–524 (initialize/prompt), 583–622
(resume/wait), 671–704 (shutdown), 713–742 (complete dispatch table), and
765–795 (actual Agent create/resume). Types are in
`dsh-session/lib/types/types.d.ts` and `dsh-llm/lib/types/message.d.ts`.

## Approval is an actual interaction, not a claimed default gate

If a tool asks for approval, the server sends a **request** with its own string
ID `req_<uuid>`, method `approval/request`, and params containing session ID,
tool name, optional call ID and reason. Reply using that exact ID and
`result:{outcome:"allowed-once"}` or `rejected`/`cancelled`. The request does not
include arguments: associate its call ID with the earlier `tool/call` event
before presenting/deciding the concrete operation. Unknown requests fail closed.

The new helper has an explicit approval callback and otherwise replies
`rejected`; it never grants automatically. The stock sdk-minimal composition
does not mount the approval service and uses full-access filesystem/shell
operations, so a normal allowed operation generally sends no approval request.
`approvalRequests:true` enables transport forwarding; it does not make every tool
require approval. Zero requests therefore establish no approval workflow. An
actual approval-specific test requires a documented composition/operation that
requests approval and its `approval/asked` → `approval/decided` audit pair.

Tool-call observation is not a pre-execution permission interceptor. The test's
small task and explicit test project scope do not turn event validation into a
hostile-code security guarantee.

## Real model and credential boundary

The published adapter registers provider `deepseek-official`. Its default root
is `https://api.deepseek.com/anthropic`; it uses the **Messages protocol**, not
OpenAI Chat Completions. `DEEPSEEK_BASE_URL` can select a compatible configured
root. Config field `apiKeyEnv` defaults to `DEEPSEEK_API_KEY`, and authentication
uses `x-api-key`. With a credential and the official origin, initialization may
refresh `/models`; without one, generation fails with `MISSING_CREDENTIAL`.

Do not put an actual key in ordinary RuntimeClient `env`, argv, JSON request,
instrumentation arguments or logs: execution requests are persisted. The
explicit `secretEnv` path passed synthetic Android tests. The test-only
one-shot bridge and dedicated synthetic sender are separate from the guest
Agent protocol; the caller owns the transient credential and clears its
array after its last authorized launch. The helper contains only public route
selectors and harmless environment entries.
No desktop Harness call can replace guest model execution.

For final acceptance, bind the run to the user's chosen **real** endpoint and
model, record nonsensitive route identity, then observe successful original
adapter/provider output. A local mock is useful for protocol development but
cannot satisfy this gate; `source.kind="model"` alone cannot distinguish a mock
endpoint. TLS certificate verification must remain enabled.

The host's installed DSH base profile (bundled 0.2.1-rc.3) specifies
`agent-default-model.config.provider=deepseek-official` and `model=deepseek-flash`;
its official API-key adapter defaults to `https://api.deepseek.com/anthropic`.
The inspected desktop profile has no override for those fields. The web profile
selects another provider as its global default but does not override the
DeepSeek route. The authorized test explicitly selects DeepSeek. Reuse the
managed `refs.DEEPSEEK_API_KEY` through the one-shot bridge, not the entire
host configuration. The guest package remains the pinned 0.2.2-rc.1. Existing
synthetic validation does not establish a successful credentialed model call.

## Minimal real workflow and new helpers

`android/probeapp/src/androidTest/kotlin/com/sucrune/probe/tests/DshAgentChecks.kt`
defines four unhooked cases:

1. Prepare a fresh private HOME, work directory and the documented file-tool
   overlay in a caller-owned project containing the verified fixture.
2. Initialize and send one real prompt requiring exactly original `write`,
   `read`, then persistent `bash`. The file tool creates a random marker line;
   Bash's actual builtin `read`/`printf` copies it to a second artifact. Require
   successful model/tool events, completed turn, shutdown response, exit zero,
   runner wait and all four cleanup barriers. Independently read both artifacts
   through the manager, then validate complete UTF-8, strict JSONL records and
   the original event identities. Report the history byte count, not its contents.
3. Start a new native runner with the same HOME, resume the same session and ask
   the real model to repeat the old random marker **without supplying it again
   or using any tools**. Check the response, new durable user message, unchanged
   original JSONL prefix, preserved artifacts, exit zero and cleanup.
4. In another fresh worker, initialize and resume the same session, then issue a
   real no-tools prompt capped at 512 tokens. Require the new user-message ID,
   a new `turn/start` and a new `session.status=running` with no `turn/end`
   before using `RuntimeClient.cancel`. Finishing naturally first fails the
   check. Verify durable `cancelled`, four cleanup barriers, independently
   executing another ordinary program in the project, both original artifacts
   and every complete JSONL record including the unchanged pre-cancel prefix.
   A hard stop need not flush the newest session buffer. Record provider stream
   observation only if an actual model-sourced stream was received before the
   stop. This does not invent an SDK cancel method or prove PTY subtree cleanup.

These are strict opt-in prerequisites, not skipped-success tests. The first two
model runs have 230 seconds within a 240-second cleanup envelope; the cancellation
run has 110 seconds within 120. Each uses cumulative bounded
stdin, strict JSON/unique keys, ordered replies, event/call limits and explicit
failure cleanup. Missing prerequisites mean not evaluated. Durable previews are
64 KiB per stream. The protocol client attaches a separate consuming stdout
reader at launch, after secret redaction. It accepts split UTF-8 and JSON lines,
requires a clean EOF on normal shutdown, and fails explicitly on overflow or a
partial final frame. It caps each validation frame at 1 MiB and each run at 8 MiB.

Host-visible failures are summarized with a fixed phase/category, numeric
JSON-RPC code or allowlisted provider failure classification/status where
available. Full protocol frames, remote error messages, environment snapshots
and exception chains are not written to instrumentation evidence.

`DshNativeRequirements.kt` separately prepares two credential-free prerequisites:

- Original `process.report.getReport()` must identify Linux ARM64 Node24.22.2
  and a real `glibcVersionRuntime`. It emits only these selected header fields,
  never the full report, which contains environment values.
- Original `@deepseek-ai/node-addon-system/flock@0.1.2` loads the published
  `system.node` and locks one open description. Re-locking it succeeds; an
  independent second open must return EAGAIN/EWOULDBLOCK, errno11. Closing the
  first releases its lock; locking the second succeeds; closing it allows a
  third independent open to lock. A synced marker is independently read back.
  This single-process test does not claim dup or cross-process semantics.

## Runtime behavior exercised by this acceptance

| Path | Actual implementation and required behavior |
| --- | --- |
| Persistent shell | `dsh-terminal-bash` uses `/bin/bash --noprofile --norc -i`; `subprocess-local.spawnTerminal` calls original node-pty. Its Linux native code calls `forkpty`, adjusts signal masks/handlers, and `execvp`; a waiter uses `waitpid`. Need real PTY master/slave, termios/window ioctls, session/process groups, child lifecycle and Bash dependencies. A host shell or bundled Lua cannot substitute. |
| Process ownership | subprocess-local probes user-systemd and has an explicit Linux PGID fallback. It inspects process identity/ranges and must terminate/reap descendants correctly. An unavailable scope is not evidence that a managed range was successfully isolated. |
| Durable session | JSONL first write lazily loads original `system.node`: `process.report` selects glibc, async `flock(LOCK_EX|LOCK_NB)` obtains ownership, fstat/stat compare inode/device, close releases. Real writes, fsync, directory publication and restore must work. No-op locks are invalid. |
| Model transport | Real Node DNS, TCP, TLS, HTTP streaming and abort/timeout are required. Local descriptor metadata and SDK handshake do not establish any of them. |
| Filesystem tools | Official local fs service and enabled tool schemas perform actual project reads/writes. Recorded tool success plus independent artifacts are required. |

Relevant published-source hashes (SHA256, original npm files):

| File under `@deepseek-ai` | SHA256 |
| --- | --- |
| `dsh-sdk-minimal/cordis.patch.yml` | `E4D4AF718A8876AB280DF474B5902AAF2FB47A899301962A6FF919F7F2BEABD5` |
| `dsh-sdk-jsonrpc-server/lib/index.js` | `17475B5675836C9C9C59F71F6F265F0D9FBDDF6AE001E9E1A213E4CFA3784D9B` |
| `dsh-llm-deepseek-api-key/lib/index.js` | `269BD9CFA20C6BC9F96D7487D36C94A5F7DBC5C40BFE3C33BC263FC94C30A07C` |
| `dsh-llm-deepseek/lib/index.js` | `955DC7BC7CA6C857FF4A7E373B87C143B96A4C43FC80325B67DC0982600DCC75` |
| `dsh-terminal-bash/lib/index.js` | `5F018757298E7A1995E2F8D7C47ECD7F016207DA1D078394A3C6B38B13AE048B` |
| `dsh-subprocess-local/lib/index.js` | `2964D94D6AA735F79E5CD5F54035A9D73B371E8060DDA7E3BF666593428C04F4` |
| `dsh-session-persistence-jsonl/lib/index.js` | `69EFEF5F84DDDF947032BC1425067878FA610416C8885ACDE2DED9B01230C9B7` |

Host compilation, synthetic bridge tests and standalone ADB shell checks are
reported separately from device executions under the ordinary application UID.
The device harness removes its own test projects; both installed APKs and the
application's execution history remain available for the next run.
