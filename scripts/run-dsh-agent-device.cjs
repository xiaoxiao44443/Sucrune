'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { SessionFrames, RunStatus, MODES } = require('./instrumentation-session.cjs');
const { sendCredential, sendManagedCredential, BridgeError } = require('./send-dsh-credential.cjs');

const component = 'com.sucrune.probe.test/com.sucrune.probe.tests.ProbeInstrumentation';
const exec = promisify(execFile);
class Failure extends Error { constructor(stage) { super(stage); this.stage = stage; } }
function reject(stage) { throw new Failure(stage); }
const hostStages = new Set(('arguments descriptor yaml_integrity existing_forward forward_result forward_identity ' +
  'forward_cleanup_identity forward_cleanup adb_command device_identity duplicate_exchange credential_window credential_receipt ' +
  'instrument_exit missing_receipt device_case_failed credential_source_size credential_source_format credential_ref_missing ' +
  'credential_shape yaml_dependency credential_source_directory credential_source_changed credential_source_read ' +
  'connect connect_EACCES connect_EPERM connect_ECONNREFUSED connect_ENETUNREACH server_proof credential_source credential_frame ' +
  'acknowledgment deadline').split(' '));
function failureSummary(error) {
  const stage = (error instanceof Failure || error instanceof BridgeError) && hostStages.has(error.stage)
    ? error.stage : 'instrumentation_protocol';
  return { status:'failed', stage };
}
function options(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--synthetic' || arg === '--real-deepseek') {
      if (out.mode) reject('arguments');
      out.mode = arg === '--synthetic' ? 'synthetic' : 'real';
    } else if (arg === '--adb' || arg === '--serial') {
      const key = arg.slice(2);
      if (out[key] || !args[i + 1] || args[i + 1].startsWith('-')) reject('arguments');
      out[key] = args[++i];
    } else reject('arguments');
  }
  if (!out.mode || !out.serial || !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,126}$/.test(out.serial)) reject('arguments');
  if (out.adb && (!path.isAbsolute(out.adb) || !/^adb(?:\.exe)?$/i.test(path.basename(out.adb)))) reject('arguments');
  out.adb ??= 'adb';
  return out;
}
function instrumentArgs(mode) {
  const a = ['exec-out', 'am', 'instrument', '-m', '-w', '--no-logcat', '-e', 'probe', MODES[mode].probe];
  if (mode === 'real') {
    for (const flag of ['node','dns','linux_processes','bash','sdk','native_requirements','secrets','real_agent','keep_foreground']) {
      a.push('-e', flag, 'true');
    }
    a.push('-e', 'node_pty', '3', '-e', 'expect_debuggable', 'false');
  }
  return [...a, component];
}
function publicDescriptor(value) {
  let d;
  try { d = JSON.parse(value); } catch { reject('descriptor'); }
  // JSONObject may escape a slash in base64. Any duplicate key, escaped
  // field name or alternate value type is rejected before ADB sees the name.
  if (!d || Array.isArray(d) || typeof d !== 'object' || Object.keys(d).sort().join(',') !== 'nonce,public_key,socket,type' ||
      value.replaceAll('\\/', '/') !== JSON.stringify(d) ||
      d.type !== 'sucrune.dsh.credential.v1' || typeof d.socket !== 'string' ||
      !/^sucrune\.dsh\.credential\.[0-9a-f]{32}$/.test(d.socket) ||
      typeof d.public_key !== 'string' || typeof d.nonce !== 'string') reject('descriptor');
  return d;
}
function verifiedYamlDirectory() {
  // This complete tree digest was derived from npm yaml@2.9.1, pinned by the
  // original DSH lock (sha512-3NxN8+78...Eb2yFw==). No module path flag.
  const root = path.resolve(__dirname, '../.build/dsh-prep-study/node_modules/yaml');
  const digest = crypto.createHash('sha256'), files = [];
  let total = 0;
  try {
    for (let p = root;;) {
      if (fs.lstatSync(p).isSymbolicLink()) reject('yaml_integrity');
      const parent = path.dirname(p); if (p === parent) break; p = parent;
    }
    function visit(dir, prefix, depth) {
      if (depth > 16) reject('yaml_integrity');
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const name = prefix + entry.name;
        if (entry.isDirectory()) visit(path.join(root,name), name + '/', depth + 1);
        else if (entry.isFile() && files.length < 233) files.push(name);
        else reject('yaml_integrity');
      }
    }
    visit(root, '', 0);
    if (files.length !== 233) reject('yaml_integrity');
    for (const name of files.sort()) {
      const filename = path.join(root,name);
      const s = fs.lstatSync(filename); total += s.size;
      if (!s.isFile() || total > 4 * 1024 * 1024) reject('yaml_integrity');
      digest.update(name).update('\0').update(crypto.createHash('sha256').update(fs.readFileSync(filename)).digest()).update('\n');
    }
    if (digest.digest('hex') !== '1162476ba9d2e50a92845ffe85e678a2d1b8d6a8e07b94c1b185683213585b31') reject('yaml_integrity');
    return root;
  } catch { reject('yaml_integrity'); }
}
function mappings(output, serial, remote) {
  return output.split(/\r?\n/).map(line => line.trim().split(/\s+/)).filter(row =>
    row.length === 3 && row[0] === serial && row[2] === remote && /^tcp:[1-9]\d{0,4}$/.test(row[1]) && +row[1].slice(4) <= 65535)
    .map(row => row[1]);
}
async function withForward(adb, serial, descriptor, send) {
  const remote = 'localabstract:' + descriptor.socket;
  const list = async () => mappings(await adb(['forward','--list']), serial, remote);
  if ((await list()).length) reject('existing_forward');
  let port, installed = false, attempted = false;
  try {
    attempted = true;
    const result = await adb(['forward','--no-rebind','tcp:0',remote]);
    installed = true;
    if (!/^[1-9]\d{0,4}$/.test(result.trim()) || Number(result.trim()) > 65535) reject('forward_result');
    port = Number(result.trim());
    const active = await list();
    if (active.length !== 1 || active[0] !== 'tcp:' + port) reject('forward_identity');
    return await send(port);
  } finally {
    if (attempted) {
      const active = await list();
      if (active.length > 1 || (installed && !active.length) || (port && active[0] !== 'tcp:' + port)) reject('forward_cleanup_identity');
      if (active.length) {
        await adb(['forward','--remove',active[0]]);
        if ((await list()).length) reject('forward_cleanup');
      }
    }
  }
}
async function run(config, log = item => console.log(JSON.stringify(item))) {
  async function adb(args) {
    try {
      return (await exec(config.adb, ['-s',config.serial,...args],
        { timeout: 8000, maxBuffer: 65536, windowsHide: true, encoding:'utf8' })).stdout;
    } catch { reject('adb_command'); }
  }
  if ((await adb(['get-serialno'])).trim() !== config.serial) reject('device_identity');
  const state = new RunStatus(config.mode), frames = new SessionFrames();
  const instrument = spawn(config.adb, ['-s',config.serial,...instrumentArgs(config.mode)],
    { windowsHide: true, stdio:['ignore','pipe','ignore'] });
  const closed = new Promise(resolve => {
    instrument.once('error', () => resolve(-1));
    instrument.once('close', code => resolve(code));
  });
  let cancelled = false, bridgeError = null, exchange, accepted = false;
  const cancel = () => { cancelled = true; instrument.kill(); };
  const timer = setTimeout(cancel, config.mode === 'synthetic' ? 85_000 : 45 * 60_000);
  process.once('SIGINT', cancel); process.once('SIGTERM', cancel);
  try {
    for await (const chunk of instrument.stdout) {
      for (const event of frames.feed(chunk)) {
        const action = state.accept(event);
        if (action.descriptor !== undefined) {
          if (exchange) reject('duplicate_exchange');
          const descriptor = publicDescriptor(action.descriptor);
          exchange = withForward(adb, config.serial, descriptor, async port => {
            const permitted = () => {
              if (cancelled || state.finished || state.credentialBlocked || state.active !== state.mode.target) reject('credential_window');
            };
            const response = config.mode === 'synthetic'
              ? await sendCredential({ port, descriptor, loadCredential: () => {
                  permitted(); return Buffer.from('sucrune-synthetic-device-bridge-v1','ascii');
                } })
              : await sendManagedCredential({ port, descriptor, verifiedDirectory: () => { permitted(); return verifiedYamlDirectory(); } });
            if (response.status !== 'accepted') reject('credential_receipt');
            accepted = true;
          }).catch(error => { bridgeError = error; cancel(); });
        } else if (action.diagnostic) log({ status:'agent_diagnostic', ...action.diagnostic });
        else if (action.failed) log({ test:action.failed, status:'failed' });
        else if (action.pass) log({ test: action.pass, status:'passed' });
        else if (action.start) log({ test: action.start, status:'started' });
      }
    }
    await exchange;
    if (bridgeError) throw bridgeError;
    if (cancelled || await closed !== 0) reject('instrument_exit');
    frames.end(); state.end();
    if (state.failures) reject('device_case_failed');
    if (!accepted) reject('missing_receipt');
    return { status:'passed', mode:config.mode, passed:state.done.size, confirmed_receipts:1, removed_forwards:1 };
  } finally {
    cancelled = true;
    clearTimeout(timer); process.removeListener('SIGINT',cancel); process.removeListener('SIGTERM',cancel);
    if (instrument.exitCode === null && instrument.signalCode === null) instrument.kill();
    await exchange;
  }
}
if (require.main === module) Promise.resolve().then(() => run(options(process.argv.slice(2)))).then(
  summary => console.log(JSON.stringify(summary)),
  error => {
    // Only locally assigned stage names. Never print stderr, protobuf strings,
    // error stacks, configuration objects or a credential source exception.
    console.error(JSON.stringify(failureSummary(error))); process.exitCode = 1;
  });
module.exports = { run, options, instrumentArgs, mappings, publicDescriptor, verifiedYamlDirectory, withForward, failureSummary };
