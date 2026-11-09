"""Stage the unmodified Alpine rootfs for the optional Android instrumentation suite."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path
from urllib.request import urlopen

from debian_archive import atomic_file


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = "alpine-minirootfs-3.22.2-aarch64.tar.gz"
URL = "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/" + ARCHIVE
SHA256 = "6bf491907b705caa5fc65773fbbc1d0954530b6c455d4446f670a4c1fdcea489"


def prepare(offline):
    cache = ROOT / ".build/linux-package-cache" / ARCHIVE
    if cache.is_file():
        data = cache.read_bytes()
    elif offline:
        raise FileNotFoundError(cache)
    else:
        with urlopen(URL, timeout=60) as source:
            data = source.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("Alpine minirootfs SHA-256 mismatch")
    if not cache.is_file():
        atomic_file(cache, data)
    # Android's asset packager strips a .gz suffix and decompresses its bytes.
    output = ROOT / ".build/linux-test-assets/linux-distro"
    atomic_file(output / "rootfs.bin", data)
    directories, links, checksums = [], {}, []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for entry in archive:
            path = "/" + entry.name.removeprefix("./") if entry.name != "." else "/"
            if entry.isdir():
                directories.append(path)
            elif entry.issym():
                links[path] = entry.linkname
            elif entry.isfile():
                digest = hashlib.sha256(archive.extractfile(entry).read()).hexdigest()
                checksums.append(f"{digest}  {path}\n")
            else:
                raise ValueError(f"Unexpected member in the pinned Alpine fixture: {path}")
    inventory = {"directories": sorted(directories), "links": links, "regular_files": len(checksums)}
    atomic_file(output / "inventory.json", json.dumps(inventory).encode())
    atomic_file(output / "files.sha256", "".join(checksums).encode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    prepare(parser.parse_args().offline)
