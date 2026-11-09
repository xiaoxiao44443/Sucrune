'use strict';
// Host-only fixtures. They do not establish Linux guest/syscall support.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { installBundle, LIMITS, MAGIC } = require('./guest-install-bundle.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const buildRoot = path.resolve(__dirname, '../.build');
fs.mkdirSync(buildRoot, { recursive: true });

function fixture(t, files = [{ name: 'nested/data.txt', data: Buffer.from('hello\n'), mode: 0o644 }]) {
  const root = fs.mkdtempSync(path.join(buildRoot, 'guest-bundle-test-'));
  // Only this exact newly created directory is eligible for recursive cleanup.
  t.after(() => {
    assert.equal(path.dirname(root), buildRoot);
    assert.match(path.basename(root), /^guest-bundle-test-[A-Za-z0-9]+$/);
    fs.rmSync(root, { recursive: true, force: true });
  });
  const manifest = { schema_version: 1, format: 'sucrune-file-bundle-v1', name: 'test',
    guest_prefix: '/opt/dsh', file_count: files.length,
    total_bytes: files.reduce((sum, file) => sum + file.data.length, 0), package_count: 1,
    source_manifest_sha256: 'a'.repeat(64), files: files.map(file => ({
      path: '/opt/dsh/' + file.name, bytes: file.data.length, mode: file.mode, sha256: sha(file.data) })) };
  const bundlePath = path.join(root, 'input.gz');
  const target = path.join(root, 'opt/dsh');
  function pack(transform = bytes => bytes, mutateCompressed = bytes => bytes) {
    const index = Buffer.from(JSON.stringify(manifest));
    const length = Buffer.alloc(4); length.writeUInt32LE(index.length);
    const plain = transform(Buffer.concat([MAGIC, length, index, ...files.map(file => file.data)]));
    const gzip = mutateCompressed(zlib.gzipSync(plain));
    fs.writeFileSync(bundlePath, gzip);
    return { expectedSha256: sha(gzip), indexSha256: sha(index) };
  }
  async function install(pin) {
    return installBundle({ bundlePath, expectedSha256: pin.expectedSha256, testRoot: root });
  }
  function cleanFailure() {
    assert.equal(fs.existsSync(target), false);
    const parent = path.join(root, 'opt');
    if (fs.existsSync(parent)) assert.deepEqual(fs.readdirSync(parent), []);
  }
  return { root, manifest, bundlePath, target, pack, install, cleanFailure };
}

test('success streams payload, preserves bytes, reports hashes and limits modes', async t => {
  const large = crypto.randomBytes(3 * LIMITS.chunk + 37);
  const f = fixture(t, [
    { name: 'nested/large.bin', data: large, mode: 0o644 },
    { name: 'bin/run', data: Buffer.from('#!/usr/bin/node\n'), mode: 0o755 },
    { name: 'empty', data: Buffer.alloc(0), mode: 0o600 },
  ]);
  const pin = f.pack();
  const result = await f.install(pin);
  assert.equal(result.file_count, 3);
  assert.equal(result.total_bytes, f.manifest.total_bytes);
  assert.equal(result.manifest_sha256, pin.indexSha256);
  assert.equal(result.compressed_sha256, pin.expectedSha256);
  assert.deepEqual(fs.readFileSync(path.join(f.target, 'nested/large.bin')), large);
  assert.equal(fs.statSync(path.join(f.target, 'empty')).size, 0);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(path.join(f.target, 'nested/large.bin')).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(f.target, 'bin/run')).mode & 0o777, 0o700);
  } else {
    // Windows chmod cannot establish POSIX execute permissions.
    assert.notEqual(fs.statSync(path.join(f.target, 'bin/run')).mode & 0o200, 0);
  }
  assert.deepEqual(fs.readdirSync(path.dirname(f.target)), ['dsh']);
});

test('existing target remains untouched', async t => {
  const f = fixture(t); const pin = f.pack();
  fs.mkdirSync(f.target, { recursive: true });
  fs.writeFileSync(path.join(f.target, 'sentinel'), 'original');
  await assert.rejects(f.install(pin), /target already exists/);
  assert.equal(fs.readFileSync(path.join(f.target, 'sentinel'), 'utf8'), 'original');
  assert.deepEqual(fs.readdirSync(path.dirname(f.target)), ['dsh']);
});

test('unsafe paths, duplicate files, parent conflicts and link entries are refused', async t => {
  for (const bad of ['/opt/dsh/../escape', '/opt/dsh/a//b', '/opt/dsh/./a', '/opt/dsh/a\\b',
    '/opt/dsh/a\0b', '/opt/dsh/file:stream', '/opt/dsh-other/file', '/opt/dsh/', '/opt/dsh']) {
    await t.test(JSON.stringify(bad), async sub => {
      const f = fixture(sub); f.manifest.files[0].path = bad;
      await assert.rejects(f.install(f.pack())); f.cleanFailure();
    });
  }
  await t.test('duplicate', async sub => {
    const f = fixture(sub, [{ name: 'a', data: Buffer.from('x'), mode: 0o600 }, { name: 'a', data: Buffer.from('y'), mode: 0o600 }]);
    await assert.rejects(f.install(f.pack()), /Duplicate/); f.cleanFailure();
  });
  await t.test('file ancestor', async sub => {
    const f = fixture(sub, [{ name: 'a', data: Buffer.from('x'), mode: 0o600 }, { name: 'a/b', data: Buffer.from('y'), mode: 0o600 }]);
    await assert.rejects(f.install(f.pack()), /parent directory/); f.cleanFailure();
  });
  await t.test('link metadata', async sub => {
    const f = fixture(sub); f.manifest.files[0].linkname = '/outside';
    await assert.rejects(f.install(f.pack()), /links are not supported/); f.cleanFailure();
  });
});

test('file and compressed hashes are mandatory before publication', async t => {
  await t.test('file hash', async sub => {
    const f = fixture(sub); f.manifest.files[0].sha256 = '0'.repeat(64);
    await assert.rejects(f.install(f.pack()), /File SHA256 mismatch/); f.cleanFailure();
  });
  await t.test('compressed hash', async sub => {
    const f = fixture(sub); const pin = f.pack(); pin.expectedSha256 = '0'.repeat(64);
    await assert.rejects(f.install(pin), /Bundle SHA256 mismatch/); f.cleanFailure();
  });
});

test('gzip errors, truncated payloads and trailing decompressed bytes cannot publish', async t => {
  const corruptions = [
    ['gzip magic', x => x, gzip => { gzip[0] = 0; return gzip; }],
    ['gzip CRC', x => x, gzip => { gzip[gzip.length - 8] ^= 1; return gzip; }],
    ['gzip trailer truncation', x => x, gzip => gzip.subarray(0, gzip.length - 5)],
    ['payload truncation', plain => plain.subarray(0, plain.length - 1)],
    ['trailing bytes', plain => Buffer.concat([plain, Buffer.from('extra')])],
    ['bundle magic', plain => { plain[0] ^= 1; return plain; }],
    ['truncated u32', () => Buffer.concat([MAGIC, Buffer.alloc(2)])],
  ];
  for (const [name, plain, compressed] of corruptions) {
    await t.test(name, async sub => {
      const f = fixture(sub);
      await assert.rejects(f.install(f.pack(plain, compressed))); f.cleanFailure();
    });
  }
});

test('all declared size/count/mode bounds are checked before writing files', async t => {
  for (const field of ['files', 'file', 'total', 'mode', 'negative', 'fractional', 'sum']) {
    await t.test(field, async sub => {
      const f = fixture(sub);
      if (field === 'files') f.manifest.file_count = LIMITS.files + 1;
      if (field === 'file') f.manifest.files[0].bytes = LIMITS.file + 1;
      if (field === 'total') f.manifest.total_bytes = LIMITS.total + 1;
      if (field === 'mode') f.manifest.files[0].mode = 0o4755;
      if (field === 'negative') f.manifest.files[0].bytes = -1;
      if (field === 'fractional') f.manifest.files[0].bytes = 0.5;
      if (field === 'sum') f.manifest.total_bytes++;
      await assert.rejects(f.install(f.pack())); f.cleanFailure();
    });
  }
  await t.test('oversized manifest length', async sub => {
    const f = fixture(sub);
    const pin = f.pack(plain => { plain.writeUInt32LE(LIMITS.manifest + 1, MAGIC.length); return plain; });
    await assert.rejects(f.install(pin), /Manifest exceeds limit/); f.cleanFailure();
  });
});

test('symlink parents are refused without touching the linked location', async t => {
  const f = fixture(t); const pin = f.pack();
  const outside = path.join(f.root, 'outside'); fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, 'sentinel'), 'original');
  try { fs.symlinkSync(outside, path.join(f.root, 'opt'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (error.code === 'EPERM') { t.skip('Host does not permit symlink creation'); return; } throw error; }
  await assert.rejects(f.install(pin), /real directory/);
  assert.deepEqual(fs.readdirSync(outside), ['sentinel']);
  fs.unlinkSync(path.join(f.root, 'opt'));
});

test('Windows cannot install without an explicit test mapping', async t => {
  if (process.platform !== 'win32') { t.skip('Windows guard'); return; }
  const f = fixture(t); const pin = f.pack();
  await assert.rejects(installBundle({ bundlePath: f.bundlePath, expectedSha256: pin.expectedSha256 }), /explicit testRoot/);
  f.cleanFailure();
});
