'use strict';
// The real credential-loading function is not exported or invoked by this test.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const net = require('node:net');
const readline = require('node:readline');
const { sendCredential, parseManagedCredential, BridgeError } = require('../send-dsh-credential.cjs');
const [java, classpath, yamlDirectory] = process.argv.slice(2);
let passed = 0;
let active = 'yaml';
function pass(name) { passed++; console.log('PASS ' + name); }
async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('test deadline')), ms); })]); }
  finally { clearTimeout(timer); }
}
async function expectStage(operation, allowed) {
  try { await operation(); } catch (error) {
    assert(error instanceof BridgeError && allowed.includes(error.stage), 'expected sanitized failure stage'); return;
  }
  throw new Error('expected synthetic refusal');
}

async function peer(mode, run) {
  active = mode + '/launch';
  const child = spawn(java, ['-cp', classpath, 'com.sucrune.probe.tests.DshCredentialWireHostKt', mode], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = once(child, 'exit');
  let childError = '';
  child.stderr.on('data', bytes => {
    const klass = String(bytes).match(/(?:java\.(?:lang|net|security|io)\.|com\.sucrune\.probe\.tests\.)([A-Za-z][A-Za-z0-9]*(?:Error|Exception|Failure))/);
    if (klass) childError = klass[1];
  });
  const reader = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  const lines = reader[Symbol.asyncIterator]();
  try {
    const first = await bounded(lines.next(), 8000);
    assert(!first.done && first.value.length < 1024, 'public descriptor not available');
    const descriptor = JSON.parse(first.value);
    active = mode + '/exchange';
    await run(descriptor);
    active = mode + '/verify';
    const second = await bounded(lines.next(), 8000);
    assert(!second.done && second.value === 'PASS ' + mode, 'JVM did not verify expected synthetic result');
    const [code] = await bounded(exited, 8000); assert.equal(code, 0);
  } finally { if (childError) active += '/' + childError; reader.close(); if (child.exitCode === null) child.kill(); }
}

async function proxy(actual, mutation, run) {
  const sockets = new Set();
  const server = net.createServer(client => {
    const upstream = net.connect(actual, '127.0.0.1'); sockets.add(client); sockets.add(upstream);
    client.on('error', () => {}); upstream.on('error', () => {});
    client.on('close', () => { upstream.destroy(); sockets.delete(client); });
    upstream.on('close', () => { client.destroy(); sockets.delete(upstream); });
    upstream.pipe(client);
    let hello = true, pending = Buffer.alloc(0);
    client.on('data', chunk => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 8192) { client.destroy(); return; }
      if (pending.length < 6) return;
      if (hello) {
        const size = 6 + pending.readUInt16BE(4) + 32;
        if (pending.length < size) return;
        assert.equal(pending.length, size); upstream.write(pending); pending = Buffer.alloc(0); hello = false;
      } else {
        const size = 6 + 12 + pending.readUInt16BE(4);
        if (pending.length < size) return;
        assert.equal(pending.length, size);
        if (mutation === 'tampered') { pending[size - 1] ^= 1; upstream.write(pending); }
        else upstream.end(pending.subarray(0, size - 1));
        pending = Buffer.alloc(0);
      }
    });
  });
  const started = once(server, 'listening'); server.listen(0, '127.0.0.1'); await started;
  try { await run(server.address().port); }
  finally { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); }
}

async function main() {
  const yaml = require(yamlDirectory);
  const fromYaml = source => parseManagedCredential(Buffer.from(source), yaml);
  const good = fromYaml('version: 1\nrefs:\n  DEEPSEEK_API_KEY: "  synthetic-wire-token  "\n');
  assert(good.equals(Buffer.from('synthetic-wire-token'))); good.fill(0);
  for (const [source, stage] of [
    ['version: 0\nrefs: {}\n', 'credential_source_format'],
    ['version: 1\nrefs: {OTHER: synthetic-other}\n', 'credential_ref_missing'],
    ['version: 1\nrefs: {DEEPSEEK_API_KEY: "space inside"}\n', 'credential_shape'],
    ['version: 1\nrefs: {DEEPSEEK_API_KEY: a, DEEPSEEK_API_KEY: b}\n', 'credential_source_format']
  ]) await expectStage(() => fromYaml(source), [stage]);
  pass('pinned YAML schema reads only selected synthetic ref, trims and rejects malformed/duplicate/invalid values');

  await peer('success', async descriptor => {
    let loads = 0; const value = Buffer.from('synthetic-wire-token');
    const result = await sendCredential({ port: descriptor.port, descriptor, loadCredential: () => { loads++; return value; } });
    assert.deepEqual(result, { status: 'accepted', credential_ref: 'DEEPSEEK_API_KEY' });
    assert.equal(loads, 1); assert(value.every(x => x === 0));
  });
  pass('real Node/JVM P-256 + HKDF + AES-GCM transfer, confirmed receipt, one-use endpoint and buffer clearing');

  await peer('device_fixture', async descriptor => {
    const result = await require('../send-dsh-credential-synthetic.cjs').main(['--port', String(descriptor.port),
      '--socket', descriptor.socket, '--public-key', descriptor.public_key, '--nonce', descriptor.nonce]);
    assert.deepEqual(result, { status: 'accepted', synthetic: true, real_credential_source_read: false });
  });
  pass('dedicated Android-probe sender accepted its exact synthetic fixture without opening any credential source');

  await peer('unauthenticated', async descriptor => {
    const fake = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' });
    let loads = 0;
    await expectStage(() => sendCredential({ port: descriptor.port, descriptor: { ...descriptor, public_key: fake.toString('base64') },
      loadCredential: () => { loads++; return Buffer.from('must-never-load'); } }), ['server_proof']);
    assert.equal(loads, 0);
  });
  pass('public-key substitution rejects peer before any credential source access');

  await peer('source_refused', async descriptor => {
    let loads = 0;
    await expectStage(() => sendCredential({ port: descriptor.port, descriptor,
      loadCredential: () => { loads++; throw new BridgeError('credential_ref_missing'); } }), ['credential_ref_missing']);
    assert.equal(loads, 1);
  });
  pass('missing credential after authenticated handshake returns a safe failure without payload');

  for (const mode of ['tampered', 'truncated']) {
    await peer(mode, descriptor => proxy(descriptor.port, mode, async port => {
      let loads = 0;
      await expectStage(() => sendCredential({ port, descriptor, loadCredential: () => { loads++; return Buffer.from('synthetic-wire-token'); } }),
        ['acknowledgment', 'credential_frame']);
      assert.equal(loads, 1);
    }));
    pass(mode + ' encrypted frame rejected by actual JVM receiver; no success acknowledgment');
  }
  const malformed = { type: 'sucrune.dsh.credential.v1', socket: 'untrusted', public_key: 'invalid', nonce: 'invalid' };
  let reads = 0;
  await expectStage(() => sendCredential({ port: 1, descriptor: malformed, loadCredential: () => { reads++; } }), ['descriptor']);
  assert.equal(reads, 0);
  pass('malformed descriptor rejected before connect or source access');
  console.log('SUMMARY ' + passed + '/' + passed + ' synthetic host checks; no Android peer, ADB, real credential or model call');
}
main().catch(error => {
  const phase = error instanceof BridgeError ? error.stage : (error.code || error.constructor?.name || 'unknown');
  console.error('FAIL synthetic credential wire check: ' + active + ' [' + (/^[A-Za-z_]+$/.test(phase) ? phase : 'internal') + ']');
  process.exitCode = 1;
});
