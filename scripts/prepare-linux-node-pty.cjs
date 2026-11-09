'use strict';

// Prepare the Linux runtime files used by DSH's locked npm package. Neither
// package installation scripts nor any code extracted from an archive runs.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { parseArgs } = require('node:util');

const project = path.resolve(__dirname, '..');
const { values } = parseArgs({ options: {
  'libc-deb': { type: 'string' }, 'node-pty-tgz': { type: 'string' },
  output: { type: 'string' }, offline: { type: 'boolean', default: false },
} });
const libcName = 'libc6_2.36-9+deb12u14_arm64.deb';
const integrity = 'vORSzHXi4Ofl7HemVWpuudLqCPdaQb4LfpRCUpE5HPxhp4JYscl8zZwxh11p26v2wvW24WMwnMfLjhRLixrfxA==';
const archives = [
  { id: 'libc6', algorithm: 'sha256', digest: '01f4330719fd4f65580e16ea5a0527f372fca750e8f588d26deaf09f2d3b1cf4',
    url: 'https://deb.debian.org/debian/pool/main/g/glibc/' + libcName,
    cache: values['libc-deb'] || path.join(project, '.build', 'linux-package-cache', libcName) },
  { id: 'node-pty', algorithm: 'sha512', digest: Buffer.from(integrity, 'base64').toString('hex'),
    url: 'https://registry.npmjs.org/node-pty/-/node-pty-1.2.0-beta.15.tgz',
    cache: values['node-pty-tgz'] || path.join(project, '.build', 'dsh-tarballs', Buffer.from(integrity, 'base64').toString('hex') + '.tgz') },
];
const output = path.resolve(values.output || path.join(project, 'android/probeapp/src/androidTest/assets/linux-node-pty'));
const prefix = '/opt/dsh/node_modules/node-pty/';
const hash = (algorithm, bytes) => crypto.createHash(algorithm).update(bytes).digest('hex');
const members = [
  { package: 'libc6', member: './lib/aarch64-linux-gnu/libutil.so.1', path: '/lib/aarch64-linux-gnu/libutil.so.1' },
  ...['package.json', 'LICENSE', 'lib/index.js', 'lib/unixTerminal.js', 'lib/terminal.js', 'lib/eventEmitter2.js',
    'lib/utils.js', 'prebuilds/linux-arm64/pty.node'].map(name => ({ package: 'node-pty', member: 'package/' + name, path: prefix + name })),
];

function plain(file) {
  for (let current = path.resolve(file);;) {
    const stat = fs.lstatSync(current, { throwIfNoEntry: false });
    if (stat?.isSymbolicLink()) throw Error('Unexpected link at ' + current);
    const parent = path.dirname(current);
    if (current === parent) break;
    current = parent;
  }
}

async function verifiedArchive(info) {
  plain(info.cache);
  if (!fs.existsSync(info.cache)) {
    if (values.offline) throw Error('Missing cached package ' + info.id);
    const response = await fetch(info.url);
    if (!response.ok) throw Error('Package download failed (' + response.status + ')');
    const bytes = Buffer.from(await response.arrayBuffer());
    if (hash(info.algorithm, bytes) !== info.digest) throw Error('Downloaded package checksum mismatch: ' + info.id);
    fs.mkdirSync(path.dirname(info.cache), { recursive: true });
    const partial = info.cache + '.' + crypto.randomUUID() + '.part';
    try { fs.writeFileSync(partial, bytes, { flag: 'wx' }); fs.renameSync(partial, info.cache); }
    finally { fs.rmSync(partial, { force: true }); }
  }
  if (hash(info.algorithm, fs.readFileSync(info.cache)) !== info.digest) throw Error('Cached package checksum mismatch: ' + info.id);
}

function publish(file, bytes) {
  plain(file);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = file + '.' + crypto.randomUUID() + '.part';
  try { fs.writeFileSync(temp, bytes, { flag: 'wx' }); fs.renameSync(temp, file); }
  finally { fs.rmSync(temp, { force: true }); }
}

async function main() {
  plain(output);
  const manifestFile = path.join(output, 'manifest.json');
  plain(manifestFile);
  if (fs.existsSync(manifestFile) && JSON.parse(fs.readFileSync(manifestFile)).name !== 'linux-arm64-node-pty') {
    throw Error('Output contains a different fixture');
  }
  for (const info of archives) await verifiedArchive(info);
  const scratchParent = path.join(project, '.build');
  plain(scratchParent);
  fs.mkdirSync(scratchParent, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(scratchParent, 'node-pty-extract-'));
  try {
    const files = [];
    for (const info of archives) {
      const dir = path.join(scratch, info.id);
      fs.mkdirSync(dir);
      let archive = path.resolve(info.cache);
      if (info.id === 'libc6') {
        execFileSync('tar', ['-xf', archive, '-C', dir, 'data.tar.xz']);
        archive = path.join(dir, 'data.tar.xz');
      }
      const wanted = members.filter(m => m.package === info.id);
      execFileSync('tar', ['-xf', archive, '-C', dir, ...wanted.map(m => m.member)]);
      for (const entry of wanted) {
        const source = path.join(dir, entry.member);
        plain(source);
        if (!fs.lstatSync(source).isFile()) throw Error('Expected a regular file ' + entry.member);
        const bytes = fs.readFileSync(source);
        if (entry.path.endsWith('package.json')) {
          const pkg = JSON.parse(bytes);
          if (pkg.name !== 'node-pty' || pkg.version !== '1.2.0-beta.15') throw Error('Unexpected package identity');
        }
        if (entry.path.endsWith('.node') || entry.path.endsWith('.so.1')) {
          if (!bytes.subarray(0, 6).equals(Buffer.from([127,69,76,70,2,1])) ||
              bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== 183) throw Error('Expected AArch64 ELF64 DSO');
        }
        const asset = 'files' + entry.path;
        publish(path.join(output, asset), bytes);
        files.push({ path: entry.path, asset, mode: 420, bytes: bytes.length, sha256: hash('sha256', bytes),
          package: entry.package, archive_member: entry.member });
      }
    }
    const manifest = { schema_version: 1, name: 'linux-arm64-node-pty', version: '1.2.0-beta.15',
      base: 'linux-rootfs with Node 24 and corresponding libc6 copyright', files,
      packages: archives.map(({ id, url, algorithm, digest }) => ({ id, url, algorithm, digest })) };
    publish(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
    console.log('Prepared ' + files.length + ' verified node-pty fixture files.');
  } finally {
    if (path.dirname(scratch) !== scratchParent || !path.basename(scratch).startsWith('node-pty-extract-')) throw Error('Invalid scratch path');
    plain(scratch);
    fs.rmSync(scratch, { recursive: true });
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
