'use strict';
// android.am.Session, emitted one top-level protobuf field at a time by "am instrument -m".
// https://android.googlesource.com/platform/frameworks/base/+/master/cmds/am/proto/instrumentation_data.proto
const MAX_FRAME = 2 * 1024 * 1024;
const fail = () => { throw new Error('invalid_instrumentation_protocol'); };
const utf8 = new TextDecoder('utf-8', { fatal: true });
const metricNames = ['event_count','tool_count','http_status','rpc_code'];
const diagnosticNames = ['stage','safe_reason','error_kind',...metricNames];
const diagnosticKeys = new Set(['id','test','current','numtests',...diagnosticNames]);
const retained = new Set(['id','test','current','numtests','credential_bridge_descriptor','passed','failed','expected_tests','probe','foreground_validation',...diagnosticNames]);
const integers = new Set(['current','numtests','passed','failed','expected_tests',...metricNames]);
const bundleKeys = new WeakMap();
const agentCases = new Set(['linux_dsh_agent_prepare','linux_dsh_agent_model_file_shell',
  'linux_dsh_agent_restart_resume','linux_dsh_agent_cancel_active_turn']);
// Host logs case names only from this installed suite's public catalog.
const realCases = new Set([...agentCases, ...(
  'argv_and_reuse dsh_native_flock_conflict_release dsh_native_process_report dsh_profile_install_bundle dsh_profile_prepare dsh_persistent_bash_tool ' +
  'dsh_sdk_initialize_shutdown dsh_sdk_minimal_eof dynamic_hello fork_cancel_session_lease gnu_bash_builtins ' +
  'guest_fork_continuation_and_wait guest_fork_exec_debian_hello guest_fork_unlinked_file_and_cwd guest_fork_stop_continue_wait guest_pselect6_mask_and_readiness ' +
  'import_upstream invalid_image_and_permissions last_instruction_trap loader_dependency_list local_io_concurrency ' +
  'node_cares_dns_records node_crypto_workflow node_esm_argv_unicode node_fs_workflow node_glibc_dns_lookup ' +
  'node_interactive_empty_cancel node_interactive_empty_timeout node_interactive_guest_closes_stdin node_interactive_roundtrip_eof ' +
  'node_javascript node_jit_optimization node_jitless node_outbound_https_certificate node_parallel_projects node_live_stdout_roundtrip node_live_stdout_overflow node_owned_proc_stat node_owned_child_kill_wait ' +
  'node_pty_bash node_pty_load node_pty_open node_pty_stty_echo node_pty_job_control node_secret_cancel_cleanup node_secret_output_events node_spawn_bash_with_connected_tcp ' +
  'node_spawn_debian_hello_with_pipes node_timers_promises node_udp_multiple_datagrams node_version node_worker_shared_atomics ' +
  'project_boundary runner_cancel_and_closed_stdin runner_exit_without_stdin_read runner_timeout signal_delivery_and_return ' +
  'thread_exit_group thread_parallel_and_join').split(' ').map(name => 'linux_' + name)]);
const stages = new Set(('prerequisite prepare credential_wait credential_received launch initialize resume prompt wait ' +
  'model_stream tool_write tool_read tool_bash tool_other tool_result turn_end turn_evidence shutdown ' +
  'terminal_evidence artifacts jsonl cancel_observe cancel reuse').split(' '));
const reasons = new Set(('progress rpc_error turn_error capture_limit partial_frame exit_before_reply deadline tool_error ' +
  'assertion runtime_error invalid_schema protocol_io cleanup unexpected history_selection history_size history_read ' +
  'history_framing history_identity history_path history_prefix history_append history_message').split(' '));
const kinds = new Set(('none AUTH QUOTA RATE_LIMIT SERVER TRANSPORT MISSING_CREDENTIAL INVALID_CREDENTIAL INVALID_REQUEST ' +
  'CONTEXT_WINDOW_EXCEEDED EMPTY_RESPONSE TOOL_ACTIVATION_FAILED UNKNOWN other').split(' '));
const rpcCodes = new Set([0,-32700,-32600,-32601,-32602,-32603,-32000]);

function fields(bytes) {
  let offset = 0;
  function varint() {
    let n = 0n;
    for (let i = 0; i < 10 && offset < bytes.length; i++) {
      const b = bytes[offset++];
      if (i === 9 && b > 1) fail();
      n |= BigInt(b & 127) << BigInt(i * 7);
      if (!(b & 128)) { if (i && !b) fail(); return n; }
    }
    fail();
  }
  const entries = [];
  while (offset < bytes.length) {
    if (entries.length >= 64) fail();
    const key = varint();
    if (key < 8n || key > 0xffffffffn) fail();
    const n = Number(key >> 3n), wire = Number(key & 7n);
    let value;
    if (wire === 0) value = varint();
    else {
      let count;
      if (wire === 2) count = Number(varint());
      else if (wire === 1 || wire === 5) count = wire === 1 ? 8 : 4;
      else fail();
      if (!Number.isSafeInteger(count) || count > bytes.length - offset) fail();
      value = bytes.subarray(offset, offset + count); offset += count;
    }
    entries.push({ n, wire, value });
  }
  return entries;
}
function text(bytes, max) {
  if (bytes.length > max) fail();
  try { return utf8.decode(bytes); } catch { fail(); }
}
function sint32(value) {
  if (value > 0xffffffffn) fail();
  return Number((value >> 1n) ^ -(value & 1n));
}
function bundle(bytes) {
  const values = new Map(), seen = new Set();
  for (const entry of fields(bytes)) {
    if (entry.n !== 1 || entry.wire !== 2) fail();
    const row = fields(entry.value);
    const keys = row.filter(f => f.n === 1), data = row.filter(f => f.n !== 1);
    if (keys.length !== 1 || keys[0].wire !== 2 || data.length > 1) fail();
    const key = text(keys[0].value, 128);
    if (seen.has(key)) fail();
    seen.add(key);
    // Stream, error text, byte blobs and nested Bundles are never interpreted.
    if (!retained.has(key)) continue;
    const f = data[0];
    if (integers.has(key)) {
      if (!f) values.set(key, 0); // ProtoOutputStream omits scalar zero.
      else if (f.n === 3 && f.wire === 0) values.set(key, sint32(f.value));
      else fail();
    } else {
      if (!f || f.n !== 2 || f.wire !== 2) fail();
      values.set(key, text(f.value, key === 'credential_bridge_descriptor' ? 1024 : 160));
    }
  }
  bundleKeys.set(values, seen);
  return values;
}
function decode(tag, bytes) {
  const session = tag === 18;
  let code = 0, finishCode = 0, values;
  const seen = new Set();
  for (const f of fields(bytes)) {
    if (seen.has(f.n)) fail();
    seen.add(f.n);
    if (f.n === 3 && f.wire === 0) code = sint32(f.value);
    else if (f.n === 4 && f.wire === 2) values = bundle(f.value);
    else if (session && f.n === 1 && f.wire === 0) {
      if (f.value > 1n) fail(); finishCode = Number(f.value);
    } else if (session && f.n === 2) fail(); // aborted session error text
    else fail(); // unexpected logcat etc.: fixed --no-logcat protocol
  }
  if (!values || finishCode !== 0) fail();
  return { session, code, values };
}

// Keep one bounded frame, including when adb splits every byte separately.
class SessionFrames {
  constructor() { this.tag = 0; this.frame = null; this.total = 0; this.count = 0; }
  feed(bytes) {
    this.total += bytes.length;
    if (this.total > 16 * MAX_FRAME) fail();
    const events = [];
    let i = 0;
    while (i < bytes.length) {
      if (!this.tag) {
        this.tag = bytes[i++];
        if (this.tag !== 10 && this.tag !== 18 || ++this.count > 768) fail();
        this.size = 0; this.shift = 0;
      } else if (!this.frame) {
        const b = bytes[i++];
        this.size += (b & 127) * 2 ** this.shift;
        if (this.size > MAX_FRAME || this.shift > 21) fail();
        if (b & 128) { this.shift += 7; continue; }
        if (!b || !this.size) fail();
        this.frame = Buffer.allocUnsafe(this.size); this.written = 0;
      } else {
        const n = Math.min(this.size - this.written, bytes.length - i);
        bytes.copy(this.frame, this.written, i, i + n); i += n; this.written += n;
        if (this.written === this.size) {
          events.push(decode(this.tag, this.frame));
          this.frame = null; this.tag = 0;
        }
      }
    }
    return events;
  }
  end() { if (this.tag || !this.count) fail(); }
}

const MODES = {
  synthetic: { id:'SucruneCredentialBridge', bridgeId:'SucruneCredentialBridge',
    target:'synthetic_android_credential_bridge', probe:'credential_bridge_synthetic' },
  real: { id:'SucruneLinux', bridgeId:'SucruneAgentCredential',
    target:'linux_dsh_agent_model_file_shell', probe:'linux' },
};
class RunStatus {
  constructor(mode) {
    this.mode = MODES[mode]; if (!this.mode) fail();
    this.active = null; this.total = 0; this.done = new Set();
    this.descriptorSeen = false; this.finished = false; this.foreground = false;
    this.failures = 0; this.credentialBlocked = false;
    this.progressStages = new Set(); this.diagnosticFailure = false;
  }
  accept({ session, code, values: v }) {
    if (this.finished) fail();
    const descriptor = v.get('credential_bridge_descriptor');
    const diagnostic = v.get('id') === 'SucruneAgentDiagnostic';
    if (diagnostic && (session || code !== 2 || this.mode !== MODES.real || descriptor !== undefined)) fail();
    if (!diagnostic && diagnosticNames.some(name => v.has(name))) fail();
    if (session) {
      if (descriptor !== undefined || this.active || (!this.descriptorSeen && !this.failures) ||
          code !== (this.failures ? 0 : -1) || !this.total || v.get('probe') !== this.mode.probe ||
          v.get('failed') !== this.failures || v.get('expected_tests') !== this.total ||
          v.get('passed') !== this.total - this.failures || this.done.size !== this.total) fail();
      this.finished = true;
      return { passed: this.total - this.failures };
    }
    if (code === 2 && v.get('foreground_validation') === 'true' && !this.foreground && !this.total && v.size === 1) {
      this.foreground = true; return {};
    }
    const id = v.get('id'), test = v.get('test'), current = v.get('current'), total = v.get('numtests');
    if (!Number.isInteger(total) || total < 1 || total > 256 || (this.total && total !== this.total) ||
        current !== this.done.size + 1 || current > total || typeof test !== 'string' || !/^[a-z][a-z0-9_]{0,95}$/.test(test)) fail();
    if (this.mode === MODES.synthetic && (total !== 1 || test !== this.mode.target)) fail();
    if (this.mode === MODES.real && !realCases.has(test)) fail();
    this.total = total;
    if (code === 1 && id === this.mode.id && !this.active && !this.done.has(test) && descriptor === undefined) {
      this.progressStages.clear(); this.diagnosticFailure = false;
      this.eventCount = 0; this.toolCount = 0;
      this.active = test; return { start: test };
    }
    if (test !== this.active) fail();
    if (diagnostic) {
      if (!agentCases.has(test) || this.diagnosticFailure) fail();
      const keys = bundleKeys.get(v);
      if (!keys || keys.size !== diagnosticKeys.size || [...keys].some(key => !diagnosticKeys.has(key))) fail();
      const stage = v.get('stage'), safe_reason = v.get('safe_reason'), error_kind = v.get('error_kind');
      const event_count = v.get('event_count'), tool_count = v.get('tool_count');
      const http_status = v.get('http_status'), rpc_code = v.get('rpc_code');
      if (!stages.has(stage) || !reasons.has(safe_reason) || !kinds.has(error_kind) ||
          !Number.isInteger(event_count) || event_count < 0 || event_count > 2048 ||
          !Number.isInteger(tool_count) || tool_count < 0 || tool_count > 8 ||
          !Number.isInteger(http_status) || (http_status !== 0 && (http_status < 100 || http_status > 599)) ||
          !rpcCodes.has(rpc_code) || event_count < this.eventCount || tool_count < this.toolCount) fail();
      this.eventCount = event_count; this.toolCount = tool_count;
      if ((stage === 'credential_wait' || stage === 'credential_received') &&
          (test !== this.mode.target || (safe_reason === 'progress' && (stage === 'credential_received') !== this.descriptorSeen) ||
           event_count || tool_count)) fail();
      if (safe_reason === 'progress') {
        if (this.progressStages.has(stage) || error_kind !== 'none' || http_status !== 0 || rpc_code !== 0) fail();
        this.progressStages.add(stage);
      } else { this.diagnosticFailure = true; this.credentialBlocked = true; }
      return { diagnostic:{ test, stage, safe_reason, error_kind, event_count, tool_count, http_status, rpc_code } };
    }
    if (code === 2 && id === this.mode.bridgeId && test === this.mode.target && !this.descriptorSeen && descriptor !== undefined) {
      if (this.credentialBlocked) fail();
      if (this.mode === MODES.real && !['linux_node_pty_bash','linux_node_outbound_https_certificate',
        'linux_node_fs_workflow','linux_node_owned_proc_stat','linux_node_pty_job_control','linux_dsh_persistent_bash_tool',
        'linux_dsh_profile_install_bundle','linux_dsh_sdk_initialize_shutdown'].every(name => this.done.has(name))) fail();
      this.descriptorSeen = true; return { descriptor };
    }
    if (code === -2 && id === this.mode.id && descriptor === undefined) {
      this.failures++; this.credentialBlocked = true; this.done.add(test); this.active = null;
      return { failed: test };
    }
    if (this.diagnosticFailure) fail();
    if (code !== 0 || id !== this.mode.id || descriptor !== undefined || (test === this.mode.target && !this.descriptorSeen)) fail();
    this.done.add(test); this.active = null; return { pass: test };
  }
  end() { if (!this.finished) fail(); }
}
module.exports = { SessionFrames, RunStatus, MODES, MAX_FRAME };
