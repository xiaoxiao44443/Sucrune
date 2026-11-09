"""Build the Debian ARM64 stty test overlay from exact, verified package members."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    ("coreutils", "9.1-1", "c/coreutils", "ec8f090a14c684879dce251254d8d9ed0876d4480f750d5807ef04e5435e1c4d"),
    ("base-files", "12.4+deb12u15", "b/base-files", "b1272fbdc197f7d5bd22c05b741a03840f8bec66ca68c8d797f567ff2c99d42d"),
)
MEMBERS = {
    "coreutils": [("./bin/stty", "/usr/bin/stty", 0o755),
                  ("./usr/share/doc/coreutils/copyright", "/usr/share/doc/coreutils/copyright", 0o644)],
    "base-files": [("./usr/share/common-licenses/GPL-3", "/usr/share/common-licenses/GPL-3", 0o644)],
}


def ar_member(data, name):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Invalid Debian archive header")
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        size = int(header[48:58].strip())
        offset += 60
        if header[58:] != b"`\n" or size < 0 or offset + size > len(data):
            raise ValueError("Invalid Debian archive member")
        if header[:16].strip().rstrip(b"/").decode("ascii") == name:
            return data[offset:offset + size]
        offset += size + size % 2
    raise ValueError("Missing Debian archive member " + name)


def atomic_file(path, payload):
    path.parent.mkdir(exist_ok=True, parents=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
        try:
            tmp.write(payload)
            tmp.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    args.add_argument("--output", type=Path, default=ROOT / "android/probeapp/src/androidTest/assets/linux-stty")
    args.add_argument("--readelf", required=True, help="Path to llvm-readelf or GNU readelf")
    args.add_argument("--offline", action="store_true")
    opts = args.parse_args()
    manifest = {"schema_version": 1, "name": "debian-bookworm-arm64-stty", "version": "9.1-1", "packages": [], "files": []}
    for package, version, pool, expected in PACKAGES:
        filename = f"{package}_{version}_arm64.deb"
        url = f"https://deb.debian.org/debian/pool/main/{pool}/{filename}"
        cache = opts.cache / filename
        if cache.is_file():
            data = cache.read_bytes()
        elif opts.offline:
            raise FileNotFoundError(cache)
        else:
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read(8 * 1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("Debian package checksum mismatch for " + filename)
        if not cache.exists():
            atomic_file(cache, data)
        manifest["packages"].append({"name": package, "version": version, "architecture": "arm64", "url": url,
            "sha256": expected, "checksum_source": f"https://packages.debian.org/bookworm/arm64/{package}/download"})
        with tarfile.open(fileobj=io.BytesIO(ar_member(data, "data.tar.xz")), mode="r:xz") as archive:
            for member, guest, mode in MEMBERS[package]:
                info = archive.getmember(member)
                if not info.isfile() or info.size > 2 * 1024 * 1024:
                    raise ValueError("Unexpected Debian package member " + member)
                with archive.extractfile(info) as stream:
                    payload = stream.read()
                asset = "files" + guest
                target = opts.output / asset
                atomic_file(target, payload)
                manifest["files"].append({"path": guest, "asset": asset, "mode": mode, "package": package,
                    "member": member, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
                if guest == "/usr/bin/stty":
                    headers = subprocess.check_output([opts.readelf, "-W", "-h", "-l", "-d", str(target)], text=True)
                    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", headers)
                    if not re.search(r"Machine:\s+AArch64", headers) or "[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]" not in headers or needed != ["libc.so.6", "ld-linux-aarch64.so.1"]:
                        raise ValueError("Unexpected ARM64 stty ELF/interpreter/DT_NEEDED: " + str(needed))
                    manifest["elf"] = {"machine": "AArch64", "interpreter": "/lib/ld-linux-aarch64.so.1", "needed": needed}
    atomic_file(opts.output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    print(f"Prepared {len(manifest['files'])} verified stty files")


if __name__ == "__main__":
    main()
