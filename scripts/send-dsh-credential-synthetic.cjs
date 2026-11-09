'use strict';
// No fs, YAML parser, credential source or real-sender CLI invocation. This
// fixed synthetic marker can only satisfy the synthetic Android probe.
const { sendCredential, BridgeError } = require('./send-dsh-credential.cjs');
async function main(args) {
  const allowed = new Set(['--port', '--socket', '--public-key', '--nonce']);
  const opts = new Map();
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || opts.has(args[i]) || typeof args[i + 1] !== 'string') throw new BridgeError('arguments');
    opts.set(args[i], args[i + 1]);
  }
  if (opts.size !== 4 || !/^\d{1,5}$/.test(opts.get('--port'))) throw new BridgeError('arguments');
  const result = await sendCredential({ port: Number(opts.get('--port')), descriptor: {
    type: 'sucrune.dsh.credential.v1', socket: opts.get('--socket'), public_key: opts.get('--public-key'), nonce: opts.get('--nonce')
  }, loadCredential: () => Buffer.from('sucrune-synthetic-device-bridge-v1', 'ascii') });
  if (result.status !== 'accepted') throw new BridgeError('acknowledgment');
  return { status: 'accepted', synthetic: true, real_credential_source_read: false };
}
if (require.main === module) main(process.argv.slice(2)).then(
  result => process.stdout.write(JSON.stringify(result) + '\n'),
  error => { process.stderr.write(JSON.stringify({ status: 'failed', synthetic: true, stage: error instanceof BridgeError ? error.stage : 'internal' }) + '\n'); process.exitCode = 1; }
);
module.exports = { main };
