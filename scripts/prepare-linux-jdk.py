"""Prepare the Debian arm64 headless Java compiler for the compiler test APK."""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
from urllib.request import urlopen

from debian_archive import atomic_file, elf_deps, payload

ROOT = Path(__file__).resolve().parents[1]
JAVA = "/usr/lib/jvm/java-17-openjdk-arm64"
VERSION = "17.0.21+9-1~deb12u1"
SECURITY = "https://deb.debian.org/debian-security/pool/updates/main/o/openjdk-17/"
PACKAGES = {
    "jre": (SECURITY + f"openjdk-17-jre-headless_{VERSION}_arm64.deb",
            42968864, "3bba5372eb4da52de1f8063cb3c362bbee6f3eb98766753916607e132103b137"),
    "jdk": (SECURITY + f"openjdk-17-jdk-headless_{VERSION}_arm64.deb",
            71051884, "d441102f17ac45e5184aa2a8309b6d1766326036fadac5deb525bccdfcbe577a"),
    "zlib": ("https://deb.debian.org/debian/pool/main/z/zlib/zlib1g_1.2.13.dfsg-1_arm64.deb",
             82744, "52b8b8a145bbe1956bba82034f77022cbef0c3d0885c9e32d9817a7932fe1913"),
}
LIBRARIES = ("libextnet.so", "libjava.so", "libjimage.so", "libjli.so", "libmanagement.so",
             "libmanagement_ext.so", "libnet.so", "libnio.so", "libverify.so", "libzip.so", "server/libjvm.so")
BASE_LIBRARIES = {"ld-linux-aarch64.so.1", "libc.so.6", "libm.so.6", "libstdc++.so.6", "libgcc_s.so.1"}
ZERO = (SECURITY + f"openjdk-17-jre-zero_{VERSION}_arm64.deb",
        2446784, "2b102bd2f544edc5a2a246a9301f3557f964e1a2bd34b94faa17db82bf3d6d96")


def archive(cache, spec, offline):
    url, size, digest = spec
    target = cache / url.rsplit("/", 1)[1]
    if target.is_file():
        data = target.read_bytes()
    elif offline:
        raise FileNotFoundError(target)
    else:
        with urlopen(url, timeout=90) as response:
            data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Size or SHA256 mismatch for {target.name}")
    if not target.exists():
        atomic_file(target, data)
    return payload(target)


def build(cache, output, offline, vm):
    files, needed = [], set()
    packages = PACKAGES if vm == "server" else {"zero": ZERO}

    def add_file(target, data):
        if data.startswith(b"\x7fELF"):
            needed.update(elf_deps(data)[1])
        sha = hashlib.sha256(data).hexdigest()
        asset = f"files/{sha}.bin"
        atomic_file(output / asset, data)
        files.append(dict(path=target, asset=asset, bytes=len(data), sha256=sha,
                          mode=0o755 if target.startswith(JAVA + "/bin/") else 0o644))

    if vm == "zero":
        # Debian's first KNOWN VM is the launcher default. Both remain available
        # when the optional overlay is installed on top of the server JDK.
        add_file(JAVA + "/lib/jvm.cfg", b"-zero KNOWN\n-server KNOWN\n-client IGNORE\n")
    for name, spec in packages.items():
        with archive(cache, spec, offline) as package:
            members = {entry.name.removeprefix("."): entry for entry in package}
            if name == "jdk":
                requested = {JAVA + "/bin/javac": JAVA + "/bin/javac"}
            elif name == "zero":
                path = JAVA + "/lib/zero/libjvm.so"
                requested = {path: path}
            elif name == "zlib":
                path, = [p for p, e in members.items() if e.isfile() and "/libz.so.1." in p]
                requested = {"/usr/lib/aarch64-linux-gnu/libz.so.1": path}
            else:
                paths = ("bin/java", "release", "lib/ct.sym", "lib/jrt-fs.jar", "lib/modules",
                         "lib/tzdb.dat", "lib/jvm.cfg", *("lib/" + lib for lib in LIBRARIES))
                requested = {JAVA + "/" + p: JAVA + "/" + p for p in paths}
                for p, member in members.items():
                    if ((p.startswith(JAVA + "/conf/") or p.startswith(JAVA + "/lib/security/") or
                         p.startswith(JAVA + "/legal/")) and not member.isdir() and not p.endswith("/cacerts")):
                        requested[p] = p
            deb = {"zlib": "zlib1g", "zero": "openjdk-17-jre-zero"}.get(name, f"openjdk-17-{name}-headless")
            doc = f"/usr/share/doc/{deb}/copyright"
            if doc in members:
                requested[doc] = doc
            for target, original in sorted(requested.items()):
                member = members[original]
                if member.issym():
                    source = posixpath.normpath(posixpath.join(posixpath.dirname(original), member.linkname))
                    member = members[source]
                if not member.isfile():
                    raise ValueError(f"Expected regular archive member for {target}")
                add_file(target, package.extractfile(member).read())
    provided = BASE_LIBRARIES | {r["path"].split("/")[-1] for r in files}
    if needed - provided:
        raise ValueError(f"Missing ELF libraries: {sorted(needed - provided)}")
    manifest = dict(schema_version=1, name=f"debian-bookworm-arm64-jdk-{vm}",
                    vm=vm, packages=[dict(url=u, size=n, sha256=h) for u, n, h in packages.values()],
                    files=sorted(files, key=lambda row: row["path"]))
    atomic_file(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Prepared {len(files)} Java compiler fixture files ({sum(r['bytes'] for r in files)} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".build/linux-package-cache")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--vm", choices=("server", "zero"), default="server",
                        help="Prepare the base server JDK, or a small overlay selecting the Zero VM.")
    args = parser.parse_args()
    layer = "linux-jdk" if args.vm == "server" else "linux-jdk-zero"
    build(args.cache, args.output or ROOT / ".build/toolbox-inputs" / layer, args.offline, args.vm)
