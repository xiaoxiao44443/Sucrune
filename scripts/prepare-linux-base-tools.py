"""Prepare verified ARM64 BusyBox applets, ripgrep and jq for project test fixtures."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct

from debian_archive import atomic_file, elf_deps, fetch, payload

ROOT = Path(__file__).resolve().parents[1]
LIB = "/usr/lib/aarch64-linux-gnu/"
# The project receives command aliases only for these user-space utilities.
APPLETS = {
    "/bin/": """ash sh cat chgrp chmod chown cp date dd df echo false grep gunzip gzip
        kill ln ls mkdir mktemp mv ps pwd rm rmdir sed sleep tar touch true uname zcat""",
    "/usr/bin/": """[ ar awk base64 basename bunzip2 bzcat bzip2 clear cmp cut diff dirname
        dos2unix du env expand expr find fold getopt head hexdump id less md5sum
        mkfifo nl nproc od paste patch printf readlink realpath rev seq sha1sum sha256sum
        sha512sum sort stat strings tac tail tee test time timeout tr truncate tty
        uniq unlink unxz unzip wc which whoami xargs xxd xz xzcat yes""",
}
MEMBERS = {
    "base-files": [("/usr/share/common-licenses/GPL-2", "/usr/share/common-licenses/GPL-2")],
    "busybox-static": [("/bin/busybox", "/bin/busybox")],
    "ripgrep": [("/usr/bin/rg", "/usr/bin/rg")],
    "jq": [("/usr/bin/jq", "/usr/bin/jq")],
    "libjq1": [(LIB + "libjq.so.1.0.4", LIB + "libjq.so.1")],
    "libonig5": [(LIB + "libonig.so.5.3.0", LIB + "libonig.so.5")],
    "libpcre2-8-0": [(LIB + "libpcre2-8.so.0.11.2", LIB + "libpcre2-8.so.0")],
}
BASE_ABI = {"libc.so.6", "libm.so.6", "libgcc_s.so.1", "ld-linux-aarch64.so.1",
            "libpthread.so.0", "libdl.so.2"}


def busybox_aliases(data):
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", data, 16) != (2, 183):
        raise ValueError("Expected Debian's statically linked AArch64 BusyBox ET_EXEC")
    headers = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if any(struct.unpack_from("<I", data, headers + size * i)[0] == 3 for i in range(count)):
        raise ValueError("Unexpected BusyBox PT_INTERP")
    # The locked Debian build's sorted NUL-delimited applet table. Refuse dangling aliases.
    start = data.index(b"\0[\0[[\0") + 1
    end = data.index(b"\0zcat\0", start) + len(b"\0zcat")
    compiled = set(data[start:end].decode("ascii").split("\0"))
    aliases = []
    for prefix, names in APPLETS.items():
        for name in names.split():
            if name not in compiled:
                raise ValueError("Missing BusyBox applet: " + name)
            aliases.append(dict(path=prefix + name, target="/bin/busybox"))
    return sorted(aliases, key=lambda alias: alias["path"])


def build(rows, paths, output):
    files = []
    aliases = []
    needed = set()
    provided = set(BASE_ABI)
    for row, path in zip(rows, paths):
        owner = row["package"]
        license_file = "/usr/share/doc/" + owner + "/copyright"
        selected = list(MEMBERS[owner])
        if owner != "base-files":
            selected.append((license_file, license_file))
        with payload(path) as tar:
            for original, guest in selected:
                member = tar.getmember("." + original)
                if not member.isfile() or member.size > 16 * 1024 * 1024:
                    raise ValueError("Unexpected Debian member: " + original)
                data = tar.extractfile(member).read()
                if guest == "/bin/busybox":
                    aliases = busybox_aliases(data)
                elif guest.startswith(("/usr/bin/", LIB)):
                    soname, dependencies = elf_deps(data)
                    needed.update(dependencies)
                    if guest.startswith(LIB):
                        if LIB + str(soname) != guest:
                            raise ValueError("Mismatched library SONAME: " + guest)
                        provided.add(soname)
                asset = "files" + guest
                atomic_file(output / asset, data)
                files.append(dict(path=guest, asset=asset, bytes=len(data), mode=member.mode & 0o777,
                                  sha256=hashlib.sha256(data).hexdigest(), package=owner, member=original))
    if needed - provided:
        raise ValueError("Missing ARM64 libraries: " + ", ".join(sorted(needed - provided)))
    manifest = dict(schema_version=1, name="debian-bookworm-arm64-base-tools", packages=rows,
                    files=sorted(files, key=lambda item: item["path"]), aliases=aliases)
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    print(f"Prepared {len(files)} files and {len(aliases)} verified BusyBox applet names")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path, default=ROOT / ".build/toolbox-inputs/linux-base-tools")
    parser.add_argument("--offline", action="store_true")
    options = parser.parse_args()
    rows = json.loads(Path(__file__).with_name("linux-base-packages.json").read_text(encoding="utf-8"))["packages"]
    with ThreadPoolExecutor(max_workers=5) as pool:
        paths = list(pool.map(lambda row: fetch(row, options.cache, options.offline), rows))
    build(rows, paths, options.output)


if __name__ == "__main__":
    main()
