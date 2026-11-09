"""Prepare an instrumentation-only pure-Go compiler profile from the official ARM64 release."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
from urllib.request import urlopen

from debian_archive import atomic_file


ROOT = Path(__file__).resolve().parents[1]
VERSION = "go1.26.10"
ARCHIVE = VERSION + ".linux-arm64.tar.gz"
URL = "https://dl.google.com/go/" + ARCHIVE
# https://go.dev/dl/#go1.26.10
SHA256 = "3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797"
PREFIX = "/usr/local/go"
PROGRAMS = {"bin/go", "pkg/tool/linux_arm64/asm", "pkg/tool/linux_arm64/compile",
            "pkg/tool/linux_arm64/link"}


def selected(path):
    if path in PROGRAMS or path in {"VERSION", "LICENSE", "PATENTS", "go.env"}:
        return True
    if path.startswith("pkg/include/"):
        return True
    if not path.startswith("src/") or path.startswith("src/cmd/"):
        return False
    parts = PurePosixPath(path).parts
    return "testdata" not in parts and not path.endswith("_test.go")


def prepare(cache, output, offline):
    archive = cache / ARCHIVE
    if not archive.is_file():
        if offline:
            raise ValueError(f"Missing {archive}")
        with urlopen(URL, timeout=120) as response:
            download = response.read(96 * 1024 * 1024)
        if hashlib.sha256(download).hexdigest() != SHA256:
            raise ValueError("Go toolchain archive SHA-256 mismatch")
        atomic_file(archive, download)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError(f"Invalid checksum for {archive}")
    files, programs = [], set()
    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != "go" or ".." in parts:
                raise ValueError(f"Unexpected archive path {member.name}")
            path = "/".join(parts[1:])
            if not member.isfile() or not selected(path):
                continue
            with tar.extractfile(member) as stream:
                data = stream.read()
            digest = hashlib.sha256(data).hexdigest()
            asset = "files/" + digest + ".bin"
            program = path in PROGRAMS
            if program:
                if data[:6] != b"\x7fELF\x02\x01" or int.from_bytes(data[18:20], "little") != 183:
                    raise ValueError(f"{path} is not AArch64 ELF")
                programs.add(path)
            dest = output / asset
            if not dest.is_file() or hashlib.sha256(dest.read_bytes()).hexdigest() != digest:
                atomic_file(dest, data)
            files.append(dict(path=PREFIX + "/" + path, asset=asset, bytes=len(data),
                              mode=0o755 if program else 0o644, sha256=digest))
    if programs != PROGRAMS:
        raise ValueError("Incomplete Go compiler profile")
    manifest = dict(schema_version=1, name="linux-go", source=URL, archive_sha256=SHA256,
                    version=VERSION, files=sorted(files, key=lambda row: row["path"]))
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} Go toolchain files, {sum(f['bytes'] for f in files)} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-go")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    prepare(args.cache, args.output, args.offline)
