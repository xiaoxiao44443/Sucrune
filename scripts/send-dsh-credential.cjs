'use strict';
// Test-only sender. Its descriptor MUST come directly from the pinned device's
// current Sucrune instrumentation status. Never accept it from guest output.
// No adb invocation, model call, credentials in argv, temporary file or env.
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');

class BridgeError extends Error {
  constructor(stage) { super('Credential bridge failed'); this.stage = stage; }
}
const fail = stage => { throw new BridgeError(stage); };
const label = value => Buffer.from(value + '\0', 'ascii');
const u16 = value => { const b = Buffer.alloc(2); b.writeUInt16BE(value); return b; };
const field = b => Buffer.concat([u16(b.length), b]);
const magic = value => Buffer.from(value, 'ascii');
const hmac = (key, ...parts) => {
  const h = crypto.createHmac('sha256', key); for (const part of parts) h.update(part); return h.digest();
};
function b64(value, min, max) {
  if (typeof value !== 'string' || value.length > 256) fail('descriptor');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64') !== value) fail('descriptor');
  return bytes;
}
function validateDescriptor(descriptor) {
  if (!descriptor || descriptor.type !== 'sucrune.dsh.credential.v1' ||
      !/^sucrune\.dsh\.credential\.[0-9a-f]{32}$/.test(descriptor.socket)) fail('descriptor');
  const pub = b64(descriptor.public_key, 65, 128), nonce = b64(descriptor.nonce, 32, 32);
  let key;
  try { key = crypto.createPublicKey({ key: pub, format: 'der', type: 'spki' }); } catch { fail('descriptor'); }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      !key.export({ format: 'der', type: 'spki' }).equals(pub)) fail('descriptor');
  return { pub, nonce, key };
}

/** The published DSH provider reads version: 1, refs.DEEPSEEK_API_KEY. Refuse
 * other layouts, aliases, invalid UTF-8 or credentials. Do not include a YAML
 * parser exception: parser diagnostics can contain actual source lines. */
function parseManagedCredential(bytes, yaml) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 1_048_576) fail('credential_source_size');
  let document;
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    document = yaml.parseDocument(source, { prettyErrors: false, uniqueKeys: true, strict: true, logLevel: 'silent' });
  } catch { fail('credential_source_format'); }
  if (document.errors.length !== 0 || document.get('version') !== 1) fail('credential_source_format');
  const raw = document.getIn(['refs', 'DEEPSEEK_API_KEY']);
  if (typeof raw !== 'string') fail('credential_ref_missing');
  const normalized = raw.trim();
  if (!/^[\x21-\x7e]+$/.test(normalized) || normalized.length > 4079) fail('credential_shape');
  return Buffer.from(normalized, 'ascii');
}

/** Fixed, user-authorized source only. Do not resolve other credential refs,
 * records, profiles, accounts or process environment fallback. */
function loadManagedCredential(yamlDirectory) {
  let yaml;
  try {
    if (!path.isAbsolute(yamlDirectory)) fail('yaml_dependency');
    const manifest = JSON.parse(fs.readFileSync(path.join(yamlDirectory, 'package.json'), 'utf8'));
    if (manifest.name !== 'yaml' || manifest.version !== '2.9.1') fail('yaml_dependency');
    yaml = require(yamlDirectory);
  } catch { fail('yaml_dependency'); }
  const filename = path.join(os.homedir(), '.dsh', '.credentials.yaml');
  let fd, bytes;
  try {
    const directory = fs.lstatSync(path.dirname(filename));
    if (!directory.isDirectory() || directory.isSymbolicLink()) fail('credential_source_directory');
    const before = fs.lstatSync(filename);
    if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > 1_048_576) fail('credential_source_size');
    fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) fail('credential_source_changed');
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const n = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (!n) fail('credential_source_changed'); offset += n;
    }
    const extra = Buffer.alloc(1);
    try { if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail('credential_source_changed'); }
    finally { extra.fill(0); }
    return parseManagedCredential(bytes, yaml);
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    fail('credential_source_read');
  } finally { bytes?.fill(0); if (fd !== undefined) try { fs.closeSync(fd); } catch {} }
}

/** The loader is invoked only after a valid proof of the private key whose public
 * part arrived through trusted instrumentation. Its returned Buffer is consumed
 * and cleared. The Android recipient authenticates the socket's shell peer UID. */
async function sendCredential({ port, descriptor, loadCredential, timeoutMs = 30_000 }) {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60_000 ||
      typeof loadCredential !== 'function') fail('arguments');
  const device = validateDescriptor(descriptor);
  const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const hostPublic = ephemeral.publicKey.export({ format: 'der', type: 'spki' });
  const hostNonce = crypto.randomBytes(32);
  const transcript = crypto.createHash('sha256').update(Buffer.concat([label('sucrune-dsh-credential-v1'),
    field(Buffer.from(descriptor.socket, 'ascii')), field(device.pub), field(hostPublic), device.nonce, hostNonce])).digest();
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: device.key });
  const keys = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([device.nonce, hostNonce]),
    Buffer.concat([label('sucrune-dsh-credential-v1 keys'), transcript]), 64));
  shared.fill(0);
  const enc = keys.subarray(0, 32), proof = keys.subarray(32);
  const socket = new net.Socket();
  socket.on('error', () => {});
  let stage = 'connect', expired = false, value, encrypted, packet;
  const timer = setTimeout(() => { expired = true; socket.destroy(new BridgeError('deadline')); }, timeoutMs);
  try {
    const connected = once(socket, 'connect');
    socket.connect(port, '127.0.0.1');
    await connected;
    socket.setNoDelay(true);
    const incoming = socket[Symbol.asyncIterator]();
    let pending = Buffer.alloc(0);
    async function read(size) {
      while (pending.length < size) {
        const part = await incoming.next();
        if (part.done || pending.length + part.value.length > 8192) fail(stage);
        pending = Buffer.concat([pending, part.value]);
      }
      const result = pending.subarray(0, size); pending = pending.subarray(size); return result;
    }
    async function write(bytes) {
      await new Promise((resolve, reject) => socket.write(bytes, error => error ? reject(error) : resolve()));
    }
    stage = 'server_proof';
    await write(Buffer.concat([magic('SCH1'), field(hostPublic), hostNonce]));
    const answer = await read(36);
    if (!answer.subarray(0, 4).equals(magic('SSP1')) ||
        !crypto.timingSafeEqual(answer.subarray(4), hmac(proof, label('server'), transcript))) fail(stage);
    if (expired) fail('deadline');
    stage = 'credential_source';
    value = await loadCredential();
    if (!Buffer.isBuffer(value) || value.length < 1 || value.length > 4079 || value.some(x => x < 0x21 || x > 0x7e)) fail('credential_shape');
    stage = 'credential_frame';
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', enc, iv);
    cipher.setAAD(Buffer.concat([label('credential'), transcript]));
    encrypted = Buffer.concat([cipher.update(value), cipher.final(), cipher.getAuthTag()]);
    value.fill(0);
    packet = Buffer.concat([magic('SCD1'), u16(encrypted.length), iv, encrypted]);
    await write(packet);
    stage = 'acknowledgment';
    const ack = await read(36);
    if (!ack.subarray(0, 4).equals(magic('SCA1')) ||
        !crypto.timingSafeEqual(ack.subarray(4), hmac(proof, label('accepted'), transcript, iv))) fail(stage);
    return { status: 'accepted', credential_ref: 'DEEPSEEK_API_KEY' };
  } catch (error) {
    if (expired) fail('deadline');
    if (error instanceof BridgeError) throw error;
    if (stage === 'connect' && ['EACCES', 'EPERM', 'ECONNREFUSED', 'ENETUNREACH'].includes(error?.code)) fail('connect_' + error.code);
    fail(stage);
  } finally { clearTimeout(timer); socket.destroy(); keys.fill(0); value?.fill?.(0); encrypted?.fill(0); packet?.fill(0); }
}

async function cli(args) {
  const options = new Map();
  const allowed = new Set(['--port', '--socket', '--public-key', '--nonce', '--yaml-module']);
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || options.has(args[i]) || typeof args[i + 1] !== 'string') fail('arguments');
    options.set(args[i], args[i + 1]);
  }
  if (options.size < 4 || !/^\d{1,5}$/.test(options.get('--port') || '')) fail('arguments');
  const descriptor = { type: 'sucrune.dsh.credential.v1', socket: options.get('--socket'),
    public_key: options.get('--public-key'), nonce: options.get('--nonce') };
  const directory = options.get('--yaml-module') || path.resolve(__dirname, '../.build/dsh-prep-study/node_modules/yaml');
  return sendManagedCredential({ port: Number(options.get('--port')), descriptor, verifiedDirectory: () => directory });
}
// The controller verifies its pinned YAML tree inside this authenticated
// callback. The credential-file reader itself stays private to this module.
function sendManagedCredential({ port, descriptor, verifiedDirectory }) {
  return sendCredential({ port, descriptor, loadCredential: () => loadManagedCredential(verifiedDirectory()) });
}
if (require.main === module) {
  cli(process.argv.slice(2)).then(
    result => process.stdout.write(JSON.stringify(result) + '\n'),
    error => { process.stderr.write(JSON.stringify({ status: 'failed', stage: error instanceof BridgeError ? error.stage : 'internal' }) + '\n'); process.exitCode = 1; }
  );
}
module.exports = { sendCredential, sendManagedCredential, parseManagedCredential, BridgeError };
