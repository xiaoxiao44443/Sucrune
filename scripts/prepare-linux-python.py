"""Prepare the pinned Debian CPython 3.11 and pip profile for the ARM64 Linux guest."""
import argparse
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts/linux-python-packages.json"
STDLIB = "/usr/lib/python3.11/"
ARCH = "/usr/lib/aarch64-linux-gnu/"
# Provided by the matching Debian Bookworm base profile.
BASE = {"ld-linux-aarch64.so.1", "libc.so.6", "libdl.so.2", "libm.so.6", "libpthread.so.0"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.parent.mkdir(exist_ok=True, parents=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def package_bytes(pkg, cache, offline):
    filename = urllib.parse.unquote(pkg["url"].rsplit("/", 1)[1])
    path = cache / filename
    if path.is_file():
        data = path.read_bytes()
    elif offline:
        raise FileNotFoundError(path)
    else:
        with urllib.request.urlopen(pkg["url"], timeout=60) as response:
            data = response.read(pkg["bytes"] + 1)
    if len(data) != pkg["bytes"] or sha(data) != pkg["sha256"]:
        raise ValueError(f"Package integrity failure: {filename}")
    if not path.exists():
        save(path, data)
    return data


def data_tar(deb):
    if not deb.startswith(b"!<arch>\n"):
        raise ValueError("Invalid Debian package header")
    offset = 8
    while offset + 60 <= len(deb):
        header = deb[offset:offset + 60]
        length = int(header[48:58])
        offset += 60
        if header[58:] != b"`\n" or not 0 <= length <= len(deb) - offset:
            raise ValueError("Invalid ar member")
        if header[:16].strip().rstrip(b"/") in (b"data.tar.xz", b"data.tar.gz"):
            return deb[offset:offset + length]
        offset += length + length % 2
    raise ValueError("Missing data tar")


def elf_libraries(data):
    """Read DT_NEEDED and DT_SONAME directly from an AArch64 ELF64 little-endian image."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Unexpected ELF architecture")
    phoff, = struct.unpack_from("<Q", data, 32)
    entsize, count = struct.unpack_from("<HH", data, 54)
    loads, dynamic = [], None
    for i in range(count):
        typ, _, offset, va, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + entsize * i)
        if typ == 1:
            loads.append((offset, va, size))
        elif typ == 2:
            dynamic = (offset, size)
    if dynamic is None:
        return set(), None
    needed, soname, strings = [], None, None
    for offset in range(dynamic[0], sum(dynamic), 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == 0:
            break
        if tag == 1:
            needed.append(value)
        elif tag == 14:
            soname = value
        elif tag == 5:
            strings = value
    if strings is None:
        raise ValueError("Missing dynamic string table")
    base = next(o + strings - va for o, va, n in loads if va <= strings < va + n)

    def string(pos):
        end = data.index(b"\x00", base + pos)
        return data[base + pos:end].decode("ascii")

    return {string(n) for n in needed}, string(soname) if soname is not None else None


def build(cache, out, offline):
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    # Keep a virtual map. Never create host symlinks or use archive paths as Windows file names.
    regular, links = {}, {}
    for pkg in lock["packages"]:
        name = pkg["name"]
        data = package_bytes(pkg, cache, offline)
        with tarfile.open(fileobj=io.BytesIO(data_tar(data)), mode="r:*") as tar:
            for info in tar:
                normalized = PurePosixPath(info.name)
                if normalized.is_absolute() or ".." in normalized.parts:
                    raise ValueError(f"Untrusted archive member in {name}")
                path = "/" + str(normalized)
                if info.isfile():
                    with tar.extractfile(info) as stream:
                        regular[path] = (stream.read(), name)
                elif info.issym() or info.islnk():
                    base = posixpath.dirname(path) if info.issym() else "/"
                    links[path] = posixpath.normpath(posixpath.join(base, info.linkname))

    def resolve(path):
        # Debian sometimes uses a directory symlink for an entire copyright tree.
        visited = set()
        while path not in regular:
            if path in visited:
                raise ValueError(f"Debian link cycle at {path}")
            visited.add(path)
            parts = PurePosixPath(path).parts
            for i in range(len(parts), 1, -1):
                prefix = str(PurePosixPath(*parts[:i]))
                if prefix in links:
                    path = posixpath.join(links[prefix], *parts[i:])
                    break
            else:
                raise ValueError(f"Missing package file {path}")
        return regular[path]

    files, library_pool, needed = {}, {}, set()

    def publish(path, data, package, executable=False):
        if path in files:
            raise ValueError(f"Duplicate target {path}")
        digest = sha(data)
        asset = f"files/{digest}.bin"
        target = out / asset
        if not target.is_file() or sha(target.read_bytes()) != digest:
            save(target, data)
        files[path] = {"path": path, "asset": asset, "bytes": len(data), "sha256": digest,
                       "mode": 493 if executable else 420, "package": package}

    for path in regular.keys() | links.keys():
        if not path.startswith(STDLIB):
            continue
        # Keep all stdlib modules and their data. The optional config tree describes
        # extension compilation and refers to development packages outside this profile.
        if path[len(STDLIB):].startswith("config-3.11-"):
            continue
        data, name = resolve(path)
        publish(path, data, name)
        if data.startswith(b"\x7fELF"):
            needed.update(elf_libraries(data)[0])

    py, owner = resolve("/usr/bin/python3.11")
    needed.update(elf_libraries(py)[0])
    publish("/usr/bin/python3.11", py, owner, True)

    for path, (data, pkg) in regular.items():
        if not re.fullmatch(r"/(?:usr/)?lib/aarch64-linux-gnu/[^/]+\.so(?:\..+)?", path):
            continue
        deps, soname = elf_libraries(data)
        if soname:
            library_pool[soname] = data, pkg, deps
    todo, done = sorted(needed), set(BASE)
    while todo:
        name = todo.pop()
        if name in done:
            continue
        if name not in library_pool:
            raise ValueError(f"Missing ARM64 shared library {name}")
        data, pkg, deps = library_pool[name]
        done.add(name)
        publish(ARCH + name, data, pkg)
        todo.extend(sorted(deps))

    for pkg in lock["packages"]:
        path = f"/usr/share/doc/{pkg['name']}/copyright"
        data, _ = resolve(path)
        publish(path, data, pkg["name"])
    data, name = resolve("/etc/mime.types")
    publish("/etc/mime.types", data, name)

    wheel, = [p for p in regular if p.startswith("/usr/share/python-wheels/pip-") and p.endswith(".whl")]
    with zipfile.ZipFile(io.BytesIO(regular[wheel][0])) as z:
        for entry in z.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in entry.filename:
                raise ValueError(f"Untrusted wheel member {path}")
            if not entry.is_dir():
                publish("/usr/lib/python3/dist-packages/" + str(path), z.read(entry), "python3-pip-whl")

    manifest = {"schema_version": 1, "name": "debian-bookworm-python-arm64",
                "packages": lock["packages"], "provided_by_base": sorted(BASE),
                "aliases": [{"path": "/usr/bin/" + cmd, "target": "/usr/bin/python3.11"}
                            for cmd in ("python", "python3")],
                "files": [files[key] for key in sorted(files)]}
    save(out / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} Python profile files ({sum(f['bytes'] for f in files.values())} bytes)")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    p.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-python")
    p.add_argument("--offline", action="store_true")
    args = p.parse_args()
    build(args.cache, args.output, args.offline)
