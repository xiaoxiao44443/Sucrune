"""Prepare a pinned Linux ARM64 SDK layout for the optional guest AGP build test."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path
from urllib.request import urlopen

from debian_archive import atomic_file, elf_deps


ROOT = Path(__file__).resolve().parents[1]
BUILD_TOOLS = "build-tools/36.0.0/"
NATIVE_TOOLS = ("aapt", "aapt2", "aidl", "dexdump", "split-select", "zipalign")


def checked(data, row, label):
    if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError(f"Unexpected size or SHA-256 for {label}")
    return data


def prepare(sdk, cache, output, offline):
    lock = json.loads(Path(__file__).with_name("linux-gradle-sdk-lock.json").read_text())
    package = lock["native"]
    archive = cache / package["filename"]
    if archive.is_file():
        data = checked(archive.read_bytes(), package, archive)
    elif offline:
        raise FileNotFoundError(archive)
    else:
        with urlopen(package["url"], timeout=90) as response:
            data = checked(response.read(package["bytes"] + 1), package, package["url"])
        atomic_file(archive, data)

    files = []

    def emit(relative, body, executable=False):
        digest = hashlib.sha256(body).hexdigest()
        asset = f"files/{digest}.bin"
        atomic_file(output / asset, body)
        files.append(dict(path="/opt/android-sdk/" + relative, asset=asset, bytes=len(body),
                          sha256=digest, mode=0o755 if executable else 0o644))

    # Only Java/resources/SDK metadata from the host are portable. Use the
    # six actual AArch64 programs checked by sdklib BuildToolInfo for 36.0.0.
    for row in lock["sdk"]:
        path = row["source"]
        emit(path, checked((sdk / path).read_bytes(), row, path))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for name in NATIVE_TOOLS:
            path = BUILD_TOOLS + name
            member = tar.getmember("./" + path)
            if not member.isfile():
                raise ValueError(f"Expected an executable file for {path}")
            binary = tar.extractfile(member).read()
            _, needed = elf_deps(binary)
            if needed:
                raise ValueError(f"Expected the pinned static ARM64 tool {name}, found {needed}")
            emit(path, binary, executable=True)
        emit("licenses/native-build-tools-provenance.txt", tar.extractfile("./PROVENANCE.txt").read())
    manifest = dict(schema_version=1, name="linux-arm64-gradle-sdk", source=package,
                    files=sorted(files, key=lambda row: row["path"]))
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} SDK files ({sum(f['bytes'] for f in files)} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True, help="Host SDK with platform 37.0 and Build Tools 36.0.0")
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-gradle-sdk")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    prepare(args.sdk, args.cache, args.output, args.offline)
