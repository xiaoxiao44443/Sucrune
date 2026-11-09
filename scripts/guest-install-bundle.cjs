'use strict';

// Run with the actual Linux Node guest, never a substituted Android executable.
// Installation is atomic for a single trusted owner of the target parent. Node's
// rename API has no RENAME_NOREPLACE flag; hostile same-UID path races are outside
// this ownership model. No archive entry creates a symlink or a hard link.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');

const MAGIC = Buffer.from('SUCRUNE-BUNDLE-1\n', 'ascii');
const LIMITS = Object.freeze({ manifest: 16 * 1024 * 1024, files: 100000,
  file: 256 * 1024 * 1024, total: 2 * 1024 * 1024 * 1024,
  compressed: 256 * 1024 * 1024, chunk: 64 * 1024, path: 1023 });
const SHA256 = /^[0-9a-f]{64}$/;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function boundedInteger(value, maximum, name) {
  check(Number.isSafeInteger(value) && value >= 0 && value <= maximum, `Invalid ${name}`);
}

function guestPath(value) {
  check(typeof value === 'string' && value.startsWith('/') &&
    Buffer.byteLength(value, 'utf8') <= LIMITS.path && !/[\\\0:]/u.test(value), 'Invalid guest path');
  const parts = value.slice(1).split('/');
  check(parts.every(part => part !== '' && part !== '.' && part !== '..' &&
    Buffer.byteLength(part, 'utf8') <= 255), 'Invalid guest path segment');
  return parts;
}

function validateManifest(raw) {
  // Reject invalid UTF-8 instead of accepting replacement characters in paths.
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  check(manifest !== null && !Array.isArray(manifest) && typeof manifest === 'object', 'Invalid manifest');
  check(manifest.schema_version === 1 && manifest.format === 'sucrune-file-bundle-v1', 'Unsupported bundle format');
  check(typeof manifest.name === 'string' && manifest.name.length > 0 && manifest.name.length <= 512, 'Invalid bundle name');
  guestPath(manifest.guest_prefix);
  check(SHA256.test(manifest.source_manifest_sha256), 'Invalid source manifest SHA256');
  boundedInteger(manifest.package_count, LIMITS.files, 'package count');
  boundedInteger(manifest.file_count, LIMITS.files, 'file count');
  boundedInteger(manifest.total_bytes, LIMITS.total, 'total bytes');
  check(Array.isArray(manifest.files) && manifest.files.length === manifest.file_count, 'File count mismatch');
  const seen = new Set();
  let bytes = 0;
  for (const file of manifest.files) {
    check(file !== null && !Array.isArray(file) && typeof file === 'object' &&
      Object.keys(file).sort().join(',') === 'bytes,mode,path,sha256', 'Invalid file entry; links are not supported');
    guestPath(file.path);
    check(file.path.startsWith(manifest.guest_prefix + '/'), 'File escapes guest prefix');
    check(!seen.has(file.path), 'Duplicate file path');
    seen.add(file.path);
    boundedInteger(file.bytes, LIMITS.file, 'file bytes');
    boundedInteger(file.mode, 0o777, 'file mode');
    check(typeof file.sha256 === 'string' && SHA256.test(file.sha256), 'Invalid file SHA256');
    bytes += file.bytes;
    check(bytes <= LIMITS.total, 'Total payload exceeds limit');
  }
  check(bytes === manifest.total_bytes, 'Total byte count mismatch');
  for (const file of manifest.files) {
    let parent = file.path.slice(0, file.path.lastIndexOf('/'));
    while (parent.length > manifest.guest_prefix.length) {
      check(!seen.has(parent), 'File is also a parent directory');
      parent = parent.slice(0, parent.lastIndexOf('/'));
    }
  }
  return manifest;
}

function lstatOrMissing(name) {
  try { return fs.lstatSync(name); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

function plainDirectories(absolute, create) {
  const resolved = path.resolve(absolute);
  let current = path.parse(resolved).root;
  for (const component of resolved.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let info = lstatOrMissing(current);
    if (info === null && create) {
      fs.mkdirSync(current, { mode: 0o700 });
      info = fs.lstatSync(current);
    }
    check(info !== null && info.isDirectory() && !info.isSymbolicLink(), 'Parent must be a real directory');
  }
  return resolved;
}

class Reader {
  constructor(stream) {
    this.iterator = stream[Symbol.asyncIterator]();
    this.chunk = null;
    this.position = 0;
    this.received = 0;
  }
  async take(maximum) {
    if (this.chunk === null || this.position === this.chunk.length) {
      const next = await this.iterator.next();
      if (next.done) return null;
      this.chunk = next.value;
      this.position = 0;
      this.received += this.chunk.length;
      check(this.received <= MAGIC.length + 4 + LIMITS.manifest + LIMITS.total, 'Decompressed bundle exceeds limit');
    }
    const count = Math.min(maximum, this.chunk.length - this.position);
    const result = this.chunk.subarray(this.position, this.position + count);
    this.position += count;
    return result;
  }
  async exact(size) {
    const result = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const chunk = await this.take(size - offset);
      check(chunk !== null, 'Truncated bundle');
      chunk.copy(result, offset);
      offset += chunk.length;
    }
    return result;
  }
}

async function closeStream(stream) {
  if (!stream || stream.closed) return;
  await new Promise(resolve => { stream.once('close', resolve); stream.destroy(); });
}

async function installBundle(options) {
  check(options && typeof options.bundlePath === 'string', 'bundlePath is required');
  check(typeof options.expectedSha256 === 'string' && SHA256.test(options.expectedSha256), 'A lowercase expected bundle SHA256 is required');
  // Test callers explicitly opt into a sandbox root. The CLI never accepts this
  // override, and refuses Windows, so /opt cannot become a host-root write.
  check(process.platform === 'linux' || typeof options.testRoot === 'string', 'Non-Linux tests require an explicit testRoot');
  const testRoot = options.testRoot === undefined ? null : plainDirectories(options.testRoot, false);
  let descriptor = null, input = null, gunzip = null, stage = null;
  try {
    descriptor = fs.openSync(options.bundlePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const info = fs.fstatSync(descriptor);
    check(info.isFile() && info.size >= 18 && info.size <= LIMITS.compressed, 'Invalid compressed bundle size or type');
    const gzipHeader = Buffer.alloc(3);
    check(fs.readSync(descriptor, gzipHeader, 0, 3, 0) === 3 &&
      gzipHeader[0] === 0x1f && gzipHeader[1] === 0x8b && gzipHeader[2] === 8, 'Invalid gzip magic or method');
    const compressedHash = crypto.createHash('sha256');
    let compressedBytes = 0, inputEnded = false;
    input = fs.createReadStream(options.bundlePath, { fd: descriptor, autoClose: true, start: 0, highWaterMark: LIMITS.chunk });
    descriptor = null; // ReadStream now owns the only input descriptor.
    gunzip = zlib.createGunzip({ chunkSize: LIMITS.chunk, writableHighWaterMark: LIMITS.chunk, readableHighWaterMark: LIMITS.chunk });
    gunzip.on('error', () => {}); // Async iteration receives the same error.
    input.on('error', error => gunzip.destroy(error));
    input.on('data', chunk => {
      compressedBytes += chunk.length;
      if (compressedBytes > LIMITS.compressed) gunzip.destroy(new Error('Compressed bundle exceeds limit'));
      compressedHash.update(chunk);
    });
    input.on('end', () => { inputEnded = true; });
    input.pipe(gunzip);
    const reader = new Reader(gunzip);
    check((await reader.exact(MAGIC.length)).equals(MAGIC), 'Invalid bundle magic');
    const manifestLength = (await reader.exact(4)).readUInt32LE(0);
    check(manifestLength > 0 && manifestLength <= LIMITS.manifest, 'Manifest exceeds limit');
    const rawManifest = await reader.exact(manifestLength);
    const manifest = validateManifest(rawManifest);
    const target = testRoot === null ? manifest.guest_prefix : path.join(testRoot, ...guestPath(manifest.guest_prefix));
    const parent = plainDirectories(path.dirname(target), true);
    check(lstatOrMissing(target) === null, 'Installation target already exists');
    stage = fs.mkdtempSync(path.join(parent, '.sucrune-bundle-'));
    const directories = new Set([stage]);
    let written = 0;
    for (const file of manifest.files) {
      const relative = file.path.slice(manifest.guest_prefix.length + 1).split('/');
      let directory = stage;
      for (const component of relative.slice(0, -1)) {
        directory = path.join(directory, component);
        if (!directories.has(directory)) {
          try { fs.mkdirSync(directory, { mode: 0o700 }); }
          catch (error) {
            if (error.code !== 'EEXIST') throw error;
            const existing = fs.lstatSync(directory);
            check(existing.isDirectory() && !existing.isSymbolicLink(), 'Payload parent is not a real directory');
          }
          // A bounded directory cache avoids repeated broker calls without
          // retaining every ancestor of all 100,000 possible file paths.
          if (directories.size === 8192) directories.delete(directories.values().next().value);
          directories.add(directory);
        }
      }
      const destination = path.join(directory, relative[relative.length - 1]);
      const fd = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      try {
        const digest = crypto.createHash('sha256');
        let remaining = file.bytes;
        while (remaining > 0) {
          const chunk = await reader.take(Math.min(remaining, LIMITS.chunk));
          check(chunk !== null, 'Truncated file payload');
          digest.update(chunk);
          for (let offset = 0; offset < chunk.length;) {
            const count = fs.writeSync(fd, chunk, offset, chunk.length - offset);
            check(count > 0, 'File write made no progress');
            offset += count;
          }
          remaining -= chunk.length;
          written += chunk.length;
        }
        check(digest.digest('hex') === file.sha256, 'File SHA256 mismatch');
        // Preserve only the executable choice; never import set-ID or group/world
        // access bits. fchmod applies to the owned, newly created descriptor.
        fs.fchmodSync(fd, (file.mode & 0o111) !== 0 ? 0o700 : 0o600);
      } finally { fs.closeSync(fd); }
    }
    // Request actual stream completion even for an empty final file. This is
    // what makes gzip trailer/CRC/truncation errors precede publication.
    check(await reader.take(1) === null, 'Trailing decompressed bytes');
    check(inputEnded && compressedBytes === info.size, 'Compressed input changed or did not reach EOF');
    const compressedSha256 = compressedHash.digest('hex');
    check(compressedSha256 === options.expectedSha256, 'Bundle SHA256 mismatch');
    check(written === manifest.total_bytes, 'Installed byte count mismatch');
    const report = { ok: true, format: manifest.format, name: manifest.name,
      guest_prefix: manifest.guest_prefix, file_count: manifest.file_count,
      total_bytes: written, package_count: manifest.package_count,
      manifest_sha256: crypto.createHash('sha256').update(rawManifest).digest('hex'),
      source_manifest_sha256: manifest.source_manifest_sha256,
      compressed_bytes: compressedBytes, compressed_sha256: compressedSha256 };
    check(lstatOrMissing(target) === null, 'Installation target appeared before publication');
    fs.renameSync(stage, target);
    stage = null; // Published target is never part of failure cleanup.
    return report;
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
    await closeStream(input);
    await closeStream(gunzip);
    if (stage !== null) fs.rmSync(stage, { recursive: true, force: true });
  }
}

module.exports = { installBundle, LIMITS, MAGIC };
if (require.main === module) {
  const args = process.argv.slice(2);
  if (process.platform !== 'linux' || args.length !== 3 || args[1] !== '--sha256') {
    process.stderr.write('Usage (Linux guest only): node guest-install-bundle.cjs BUNDLE.gz --sha256 LOWERCASE_SHA256\n');
    process.exitCode = 2;
  } else {
    installBundle({ bundlePath: args[0], expectedSha256: args[2] }).then(
      result => process.stdout.write(JSON.stringify(result) + '\n'),
      error => { process.stderr.write(JSON.stringify({ ok: false, error: error.message }) + '\n'); process.exitCode = 1; });
  }
}
